import Foundation

private enum AutoRefreshConstants {
    static let refreshLeadTime: TimeInterval = 90
    static let minimumSleepInterval: TimeInterval = 1
}

/// This actor manages the authentication lifecycle, session persistence,
/// automatic token refresh, and events.
actor BetterAuthSessionManager {
    let configuration: BetterAuthConfiguration
    let sessionStore: BetterAuthSessionStore
    let network: AuthNetworkClient
    let logger: BetterAuthLogger?
    let state: BetterAuthSessionState
    let sessionService: BetterAuthSessionService
    let refreshService: BetterAuthSessionRefreshService
    let userAccountService: BetterAuthUserAccountService
    let callbackHandler: BetterAuthCallbackHandler
    let context: BetterAuthSessionContext
    let authThrottle = BetterAuthAuthOperationThrottle()
    var authStateListenerRegistrations: [any AuthStateChangeRegistration] = []
    var inFlightRefreshTask: Task<BetterAuthSession, Error>?
    var autoRefreshTask: Task<Void, Never>?
    var sessionGeneration = UUID()
    var credentialGeneration = UUID()
    var autoRefreshSuspended = false
    var inFlightRefreshIdentifier: UUID?
    var inFlightRefreshGeneration: UUID?

    func makeRelay() -> BetterAuthSessionEventRelay {
        let generation = sessionGeneration
        return BetterAuthSessionEventRelay(context: context,
                                           commitSession: { [weak self] session, event in
                                               guard let self else { throw CancellationError() }
                                               return try await self.commitSession(session, event: event,
                                                                                   generation: generation)
                                           })
    }

    func makeMaterializer() -> BetterAuthSessionMaterializer {
        BetterAuthSessionMaterializer(context: context)
    }

    func makeProfileService() -> BetterAuthProfileService {
        BetterAuthProfileService(context: context, relay: makeRelay(), materializer: makeMaterializer())
    }

    func makePasskeyService() -> BetterAuthPasskeyService {
        BetterAuthPasskeyService(context: context, relay: makeRelay(), materializer: makeMaterializer())
    }

    func makeOneTimeCodeService() -> BetterAuthOneTimeCodeService {
        BetterAuthOneTimeCodeService(context: context, relay: makeRelay(), materializer: makeMaterializer())
    }

    func makeTwoFactorService() -> BetterAuthTwoFactorService {
        BetterAuthTwoFactorService(context: context, relay: makeRelay(), materializer: makeMaterializer())
    }

    func makeSessionAdministrationService() -> BetterAuthSessionAdministrationService {
        BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
    }

    func throttleAuthOperation(_ operation: String) async throws {
        guard let policy = configuration.auth.throttlePolicy else { return }
        try await authThrottle.check(operation: operation, policy: policy)
    }

    init(configuration: BetterAuthConfiguration,
         sessionStore: BetterAuthSessionStore,
         transport: BetterAuthTransport,
         logger: BetterAuthLogger? = nil,
         eventEmitter: AuthEventEmitter = AuthEventEmitter(),
         authStateListeners: [any BetterAuthAuthStateListener] = [])
    {
        self.configuration = configuration
        self.sessionStore = sessionStore
        self.network = AuthNetworkClient(baseURL: configuration.baseURL,
                                         transport: transport,
                                         retryPolicy: configuration.retryPolicy,
                                         requestOrigin: configuration.requestOrigin,
                                         timeoutInterval: configuration.timeoutInterval)
        self.logger = logger
        self.state = BetterAuthSessionState(eventEmitter: eventEmitter)
        self.sessionService = BetterAuthSessionService(configuration: configuration, sessionStore: sessionStore)
        self.refreshService = BetterAuthSessionRefreshService(configuration: configuration, network: self.network)
        self.userAccountService = BetterAuthUserAccountService(configuration: configuration, network: self.network)
        self.callbackHandler = BetterAuthCallbackHandler(baseURL: configuration.baseURL,
                                                         endpoints: configuration.endpoints,
                                                         callbackURLSchemes: configuration.auth.callbackURLSchemes)
        self.context = BetterAuthSessionContext(configuration: configuration,
                                                state: self.state,
                                                sessionService: self.sessionService,
                                                refreshService: self.refreshService,
                                                userAccountService: self.userAccountService,
                                                callbackHandler: self.callbackHandler,
                                                network: self.network,
                                                logger: logger)
        self.authStateListenerRegistrations = Self.makeAuthStateListenerRegistrations(authStateListeners,
                                                                                      eventEmitter: eventEmitter)
    }

    // MARK: - Event Stream

    nonisolated var onAuthStateChange: AuthEventEmitter {
        state.eventEmitter
    }

    nonisolated var authStateChanges: AsyncStream<AuthStateChange> {
        state.stateChanges
    }

    nonisolated var accessTokenChanges: AsyncStream<String?> {
        let changes = authStateChanges
        return AsyncStream { continuation in
            let task = Task {
                for await change in changes {
                    continuation.yield(change.session?.session.accessToken)
                }
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    nonisolated var currentAuthState: AuthStateChange? {
        state.latest
    }

    // MARK: - Sign Out

    /// Signs out and clears the local session. This method can also revoke the backend session.
    func signOut(remotely: Bool = true) async throws {
        let accessToken = state.currentSession?.session.accessToken
        try clearSession(event: .signedOut)
        inFlightRefreshTask?.cancel()
        try await makeSessionAdministrationService().signOut(remotely: remotely, accessToken: accessToken)
    }

    // MARK: - Auto-Refresh

    func startAutoRefresh() {
        stopAutoRefresh()
        logger?.debug("Starting auto-refresh timer")
        guard configuration.autoRefreshToken, !autoRefreshSuspended,
              let expiresAt = state.currentSession?.session.expiresAt else { return }
        let sleepDuration = max(expiresAt.timeIntervalSinceNow - AutoRefreshConstants.refreshLeadTime,
                                AutoRefreshConstants.minimumSleepInterval)
        autoRefreshTask = Task { [weak self] in
            do {
                try await Task.sleep(for: .seconds(sleepDuration))
                try Task.checkCancellation()
                await self?.autoRefreshTimerFired()
            } catch {
                // Cancelling the timer is expected when the session changes.
            }
        }
    }

    func stopAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }

    func shutdown() {
        autoRefreshSuspended = true
        sessionGeneration = UUID()
        stopAutoRefresh()
        inFlightRefreshTask?.cancel()
        inFlightRefreshTask = nil
        authStateListenerRegistrations.forEach { $0.remove() }
        authStateListenerRegistrations.removeAll()
    }

    func applicationDidBecomeActive() async {
        autoRefreshSuspended = false
        guard configuration.autoRefreshToken, state.currentSession != nil else { return }
        startAutoRefresh()
        do {
            _ = try await refreshSessionIfNeeded()
        } catch {
            logger?.warning("Session refresh on app activation failed: \(error)")
        }
    }

    func applicationWillResignActive() {
        autoRefreshSuspended = true
        stopAutoRefresh()
    }

    deinit {
        autoRefreshTask?.cancel()
        inFlightRefreshTask?.cancel()
        authStateListenerRegistrations.forEach { $0.remove() }
    }

    func autoRefreshTimerFired() {
        guard !autoRefreshSuspended, !Task.isCancelled else { return }
        // Start the owned refresh task without holding this actor alive across network I/O.
        do {
            _ = try makeRefreshTask()
        } catch {
            logger?.warning("Automatic session refresh failed: \(error)")
        }
    }

    // MARK: - Deep Link Handling

    func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        callbackHandler.parseIncomingURL(url)
    }

    func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        switch parseIncomingURL(url) {
        case let .verifyEmail(payload):
            try await .verifyEmail(verifyEmail(payload))

        case .unsupported:
            .ignored
        }
    }

    func handle(_ url: URL) async {
        do {
            let result = try await handleIncomingURL(url)
            switch result {
            case let .verifyEmail(result):
                logger?.info("Verify email callback handled: \(result)")

            case .ignored:
                logger?.warning("Unsupported auth callback URL: \(url)")
            }
        } catch {
            logger?.error("Auth callback failed: \(error)")
        }
    }

    func installAuthStateListeners(_ listeners: [any BetterAuthAuthStateListener]) async {
        authStateListenerRegistrations.forEach { $0.remove() }
        authStateListenerRegistrations = Self.makeAuthStateListenerRegistrations(listeners,
                                                                                 eventEmitter: state.eventEmitter)
    }

    // MARK: - Session Lifecycle Helpers

    /// All session commits, persistence, notifications and timer updates run on this actor.
    @discardableResult
    func commitSession(_ session: BetterAuthSession?, event: AuthChangeEvent,
                       generation: UUID) throws -> AuthStateChange
    {
        guard generation == sessionGeneration else { throw CancellationError() }
        return try setSession(session, event: event)
    }

    @discardableResult
    func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent,
                    startsNewGeneration: Bool = false) throws -> AuthStateChange
    {
        let previous = state.currentSession
        // A profile response must not roll credentials back if a refresh finished meanwhile.
        let session = if event == .userUpdated, let previous, let session,
                         previous.user.id == session.user.id
        {
            BetterAuthSession(session: previous.session, user: session.user)
        } else {
            session
        }
        try sessionService.persist(session)
        state.replaceCurrentSession(session)
        if startsNewGeneration || event == .signedIn || event == .signedOut || event == .sessionExpired ||
            previous?.user.id != session?.user.id
        {
            sessionGeneration = UUID()
        }
        if previous?.session != session?.session {
            credentialGeneration = UUID()
        }
        let change = AuthStateChange(event: event, session: session,
                                     transition: makeRelay().transition(for: event, session: session))
        state.eventEmitter.yield(change)
        updateAutoRefresh(for: session)
        return change
    }

    func clearSession(event: AuthChangeEvent = .signedOut) throws {
        _ = try setSession(nil, event: event)
    }

    static func makeAuthStateListenerRegistrations(_ listeners: [any BetterAuthAuthStateListener],
                                                   eventEmitter: AuthEventEmitter)
        -> [any AuthStateChangeRegistration]
    {
        listeners.map { listener in
            eventEmitter.on { change in
                await listener.authStateDidChange(change)
            }
        }
    }

    func updateAutoRefresh(for session: BetterAuthSession?) {
        guard configuration.autoRefreshToken else {
            stopAutoRefresh()
            return
        }

        if session != nil {
            startAutoRefresh()
        } else {
            stopAutoRefresh()
        }
    }

    func updateEvent(from previousSession: BetterAuthSession?,
                     to updatedSession: BetterAuthSession?) -> AuthChangeEvent
    {
        switch (previousSession, updatedSession) {
        case (_, nil):
            return .signedOut

        case (nil, .some):
            return .signedIn

        case let (.some(previous), .some(updated)):
            if previous.session.accessToken != updated.session.accessToken ||
                previous.session.refreshToken != updated.session.refreshToken ||
                previous.session.expiresAt != updated.session.expiresAt
            {
                return .tokenRefreshed
            }
            return .userUpdated
        }
    }
}

struct SignOutResponse: Decodable {
    let success: Bool
}

struct RevokeSessionRequest: Encodable {
    let token: String
}

extension BetterAuthSessionManager: BetterAuthSessionLifecycle,
    BetterAuthSessionFetching,
    BetterAuthOneTimeCodePerforming,
    BetterAuthTwoFactorPerforming,
    BetterAuthPasskeyPerforming,
    BetterAuthAccountPerforming,
    BetterAuthSessionAdministrating {}
