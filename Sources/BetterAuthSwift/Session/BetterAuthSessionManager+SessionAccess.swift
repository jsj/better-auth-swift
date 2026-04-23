import Foundation

public extension BetterAuthSessionManager {
    // MARK: - Session Access

    /// Loads the persisted session from the session store without entering the actor.
    nonisolated func loadStoredSession() throws -> BetterAuthSession? {
        try sessionService.loadStoredSession()
    }

    /// Restores the session from storage into memory and starts auto-refresh if configured.
    func restoreSession() throws -> BetterAuthSession? {
        let session = try makeSessionBootstrapService().loadStoredSession()
        try applyRestoredSession(session)
        return session
    }

    /// Restores the best available session for app launch and reports how it was recovered.
    func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        let result = try await makeSessionBootstrapService()
            .restoreSessionOnLaunch(refreshSession: { try await self.refreshSession() })
        updateAutoRefresh(for: result)
        return result
    }

    /// Returns the current in-memory session, if any.
    func currentSession() -> BetterAuthSession? {
        state.currentSession
    }

    func applyRestoredSession(_ session: BetterAuthSession?) throws {
        try makeSessionBootstrapService().applyRestoredSession(session)
        updateAutoRefresh(for: session)
    }

    func updateSession(_ session: BetterAuthSession?) throws {
        let event = updateEvent(from: state.currentSession, to: session)
        _ = try makeRelay().setSession(session, event: event)
        updateAutoRefresh(for: session)
    }

    // MARK: - Session Refresh

    /// Refreshes the current session with the backend. Deduplicates concurrent calls.
    @discardableResult
    func refreshSession() async throws -> BetterAuthSession {
        if let existing = inFlightRefreshTask {
            logger?.debug("Reusing in-flight refresh task")
            return try await existing.value
        }

        guard let existingSession = state.currentSession else {
            throw BetterAuthError.missingSession
        }

        // Keep the refresh task scoped to immutable snapshots so the unstructured
        // task does not capture actor-isolated mutable state.
        let task = Task { () -> BetterAuthSession in
            try await refreshService.refresh(using: existingSession)
        }

        inFlightRefreshTask = task
        do {
            let session = try await task.value
            inFlightRefreshTask = nil
            try setSession(session, event: .tokenRefreshed)
            logger?.info("Session refreshed")
            return session
        } catch {
            inFlightRefreshTask = nil
            if makeRelay().shouldClearSession(for: error) {
                try clearSession(event: .sessionExpired)
            }
            throw error
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
        try await makeSessionBootstrapService().fetchCurrentSession()
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

    /// Restores from storage and refreshes if expired. The recommended way to bootstrap a session at app launch.
    func restoreOrRefreshSession() async throws -> BetterAuthSession? {
        let bootstrap = makeSessionBootstrapService()
        let session = try await bootstrap
            .restoreOrRefreshSession(restoreSession: { try bootstrap.restoreSession() },
                                     refreshSession: { try await self.refreshSession() })
        updateAutoRefresh(for: session)
        return session
    }

    // MARK: - Authorized Request

    func authorizedRequest(path: String, method: String = "GET") async throws -> URLRequest {
        let session = try await makeRelay().validSession()
        let url = try BetterAuthURLResolver.resolve(path, relativeTo: configuration.baseURL)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = configuration.timeoutInterval
        request.setValue("Bearer \(session.session.accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }
}
