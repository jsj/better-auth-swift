import Foundation

extension BetterAuthSessionManager {
    // MARK: - Session Access

    /// Loads the persisted session from the session store through the session actor.
    func loadStoredSession() throws -> BetterAuthSession? {
        try sessionService.loadStoredSession()
    }

    /// Restores the session from storage into memory. If configured, this method starts automatic refresh.
    func restoreSession() throws -> BetterAuthSession? {
        let session = try loadStoredSession()
        try applyRestoredSession(session)
        return session
    }

    /// Restores the best available session for app launch and reports how it was recovered.
    func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        let source: BetterAuthRestoreSource
        if state.currentSession != nil {
            source = .memory
        } else {
            do {
                _ = try restoreSession()
            } catch {
                try clearSession()
                return .cleared(.storageFailure)
            }
            source = .keychain
        }
        guard let current = state.currentSession else { return .noStoredSession }
        guard current.needsRefresh(clockSkew: configuration.auth.clockSkew) else {
            return .restored(current, source: source, refresh: .notNeeded)
        }
        do {
            return await .restored(try refreshSession(), source: source, refresh: .refreshed)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            if makeRelay().shouldClearSession(for: error) {
                return .cleared(makeRelay().clearReason(for: error))
            }
            return .restored(current, source: source, refresh: .deferred)
        }
    }

    /// Returns the current in-memory session, if any.
    func currentSession() -> BetterAuthSession? {
        state.currentSession
    }

    /// If necessary, refreshes the session. Then returns the session for authenticated requests.
    @discardableResult
    func validSession() async throws -> BetterAuthSession {
        try await refreshSessionIfNeeded()
    }

    func applyRestoredSession(_ session: BetterAuthSession?) throws {
        state.replaceCurrentSession(session)
        sessionGeneration = UUID()
        credentialGeneration = UUID()
        state.emit(.initialSession, session: session,
                   transition: .init(phase: session == nil ? .unauthenticated : .authenticated))
        updateAutoRefresh(for: session)
    }

    func updateSession(_ session: BetterAuthSession?) throws {
        let event = updateEvent(from: state.currentSession, to: session)
        try setSession(session, event: event, startsNewGeneration: true)
    }

    func applyPluginSessionOutcome(_ outcome: BetterAuthPluginSessionOutcome) async throws -> BetterAuthSession {
        let result: BetterAuthSessionOutcome = switch outcome {
        case let .signedIn(session):
            .signedIn(session)

        case let .token(token, fallbackUser):
            .token(token: token, fallbackUser: fallbackUser)
        }
        return try await BetterAuthSessionResultHandler(relay: makeRelay(), materializer: makeMaterializer())
            .appliedSession(from: result)
    }

    // MARK: - Session Refresh

    /// Refreshes the current session with the backend. Deduplicates concurrent calls.
    @discardableResult
    func refreshSession() async throws -> BetterAuthSession {
        try await makeRefreshTask().value
    }

    /// Shared refresh work owns its completion; waiters only observe the committed result.
    func makeRefreshTask() throws -> Task<BetterAuthSession, Error> {
        if let existing = inFlightRefreshTask, inFlightRefreshGeneration == sessionGeneration {
            return existing
        }
        guard let existingSession = state.currentSession else {
            throw BetterAuthError.missingSession
        }
        let generation = sessionGeneration
        let credentials = credentialGeneration
        let identifier = UUID()
        let service = refreshService
        let task = Task { [weak self] () throws -> BetterAuthSession in
            do {
                let session = try await service.refresh(using: existingSession)
                try Task.checkCancellation()
                guard let self else { throw CancellationError() }
                return try await self.finishRefresh(session, previousUser: existingSession.user, generation: generation,
                                                    credentials: credentials, identifier: identifier)
            } catch {
                guard let self else { throw CancellationError() }
                try await self.finishRefresh(error, generation: generation,
                                             credentials: credentials, identifier: identifier)
                throw error
            }
        }
        inFlightRefreshTask = task
        inFlightRefreshGeneration = generation
        inFlightRefreshIdentifier = identifier
        return task
    }

    private func finishRefresh(_ session: BetterAuthSession, previousUser: BetterAuthSession.User, generation: UUID,
                               credentials: UUID, identifier: UUID) throws -> BetterAuthSession
    {
        defer { clearRefreshTask(identifier: identifier) }
        guard generation == sessionGeneration else { throw CancellationError() }
        // A password rotation or another session fetch may already have replaced these credentials.
        if credentials != credentialGeneration {
            guard let current = state.currentSession else { throw CancellationError() }
            return current
        }
        let session = preservingUpdatedUser(in: session, previousUser: previousUser)
        try commitSession(session, event: .tokenRefreshed, generation: generation)
        return session
    }

    private func preservingUpdatedUser(in session: BetterAuthSession,
                                       previousUser: BetterAuthSession.User?) -> BetterAuthSession
    {
        guard let current = state.currentSession,
              current.user.id == session.user.id,
              current.user != previousUser else { return session }
        return BetterAuthSession(session: session.session, user: current.user)
    }

    private func finishRefresh(_ error: Error, generation: UUID,
                               credentials: UUID, identifier: UUID) throws
    {
        defer { clearRefreshTask(identifier: identifier) }
        guard credentials == credentialGeneration else { throw CancellationError() }
        try handleRefreshFailure(error, generation: generation)
        if !(error is CancellationError), state.currentSession != nil {
            logger?.warning("Session refresh failed: \(error)")
            startAutoRefresh()
        }
    }

    private func clearRefreshTask(identifier: UUID) {
        guard inFlightRefreshIdentifier == identifier else { return }
        inFlightRefreshTask = nil
        inFlightRefreshGeneration = nil
        inFlightRefreshIdentifier = nil
    }

    private func handleRefreshFailure(_ error: Error, generation: UUID) throws {
        guard generation == sessionGeneration else { throw CancellationError() }
        if makeRelay().shouldClearSession(for: error) {
            try clearSession(event: .sessionExpired)
        }
    }

    @discardableResult
    func refreshSessionIfNeeded() async throws -> BetterAuthSession {
        guard let current = state.currentSession else { throw BetterAuthError.missingSession }
        guard current.needsRefresh(clockSkew: configuration.auth.clockSkew) else { return current }
        return try await refreshSession()
    }

    @discardableResult
    func fetchCurrentSession() async throws -> BetterAuthSession {
        let generation = sessionGeneration
        let existingToken = state.currentSession?.session.accessToken
        let previousUser = state.currentSession?.user
        let credentials = credentialGeneration
        do {
            let fetched = try await refreshService.fetchCurrentSession(accessToken: existingToken)
            guard generation == sessionGeneration else { throw CancellationError() }
            if credentials != credentialGeneration, let current = state.currentSession {
                return current
            }
            let session = preservingUpdatedUser(in: fetched, previousUser: previousUser)
            try commitSession(session, event: .tokenRefreshed, generation: generation)
            return session
        } catch {
            guard credentials == credentialGeneration else { throw CancellationError() }
            try handleRefreshFailure(error, generation: generation)
            throw error
        }
    }

    // MARK: - Session Management

    func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await makeSessionAdministrationService()
            .listSessions(accessToken: state.currentSession?.session.accessToken)
    }

    func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await makeSessionAdministrationService()
            .listDeviceSessions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        try await makeSessionAdministrationService().setActiveDeviceSession(payload,
                                                                            accessToken: state.currentSession?.session
                                                                                .accessToken)
    }

    @discardableResult
    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        try await makeSessionAdministrationService()
            .revokeDeviceSession(payload,
                                 accessToken: state.currentSession?.session.accessToken,
                                 currentAccessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Session Revocation

    @discardableResult
    func revokeSession(token: String) async throws -> Bool {
        try await makeSessionAdministrationService()
            .revokeSession(token: token,
                           accessToken: state.currentSession?.session.accessToken,
                           currentAccessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func revokeSessions() async throws -> Bool {
        try await makeSessionAdministrationService()
            .revokeSessions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func revokeOtherSessions() async throws -> Bool {
        try await makeSessionAdministrationService()
            .revokeOtherSessions(accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Restore / Refresh

    /// Restores the session from storage. If the session expired, this method refreshes it.
    /// Use this method to restore a session at app launch.
    func restoreOrRefreshSession() async throws -> BetterAuthSession? {
        if state.currentSession == nil {
            do {
                _ = try restoreSession()
            } catch {
                try clearSession()
                throw error
            }
        }
        guard let current = state.currentSession else { return nil }
        if current.needsRefresh(clockSkew: configuration.auth.clockSkew) {
            return try await refreshSession()
        }
        return current
    }

    // MARK: - Authorized Request

    func authorizedRequest(path: String, method: String = "GET") async throws -> URLRequest {
        let session = try await validSession()
        return try BetterAuthHTTPRequestBuilder(configuration: configuration)
            .makeRequest(path: path, method: method, accessToken: session.session.accessToken)
    }
}
