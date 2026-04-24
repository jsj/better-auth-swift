import Foundation

private enum AutoRefreshConstants {
    static let refreshLeadTime: TimeInterval = 90
    static let minimumSleepInterval: TimeInterval = 1
}

/// Actor-isolated session manager that owns the full auth lifecycle.
///
/// Access via ``BetterAuthClient/auth``. Handles sign-in, sign-out,
/// session persistence, automatic token refresh, and event emission.
public actor BetterAuthSessionManager {
    let configuration: BetterAuthConfiguration
    let sessionStore: BetterAuthSessionStore
    let network: AuthNetworkClient
    let logger: BetterAuthLogger?
    let state: BetterAuthSessionState
    let sessionService: BetterAuthSessionService
    let refreshService: BetterAuthSessionRefreshService
    let authFlowService: BetterAuthAuthFlowService
    let userAccountService: BetterAuthUserAccountService
    let callbackHandler: BetterAuthCallbackHandler
    let context: BetterAuthSessionContext
    let authThrottle = BetterAuthAuthOperationThrottle()
    var authStateListenerRegistrations: [any AuthStateChangeRegistration] = []
    var inFlightRefreshTask: Task<BetterAuthSession, Error>?
    var autoRefreshTask: Task<Void, Never>?
    var cachedRelay: BetterAuthSessionEventRelay?
    var cachedMaterializer: BetterAuthSessionMaterializer?
    var cachedPrimaryAuthService: BetterAuthPrimaryAuthService?
    var cachedProfileService: BetterAuthProfileService?
    var cachedPasskeyService: BetterAuthPasskeyService?
    var cachedOneTimeCodeService: BetterAuthOneTimeCodeService?
    var cachedTwoFactorService: BetterAuthTwoFactorService?
    var cachedSessionAdministrationService: BetterAuthSessionAdministrationService?
    var cachedSessionBootstrapService: BetterAuthSessionBootstrapService?
    var cachedOAuthService: BetterAuthOAuthService?

    func makeRelay() -> BetterAuthSessionEventRelay {
        if let cachedRelay { return cachedRelay }
        let relay = BetterAuthSessionEventRelay(context: context,
                                                refreshSession: {
                                                    try await self.refreshSession()
                                                })
        cachedRelay = relay
        return relay
    }

    func makeMaterializer() -> BetterAuthSessionMaterializer {
        if let cachedMaterializer { return cachedMaterializer }
        let materializer = BetterAuthSessionMaterializer(context: context)
        cachedMaterializer = materializer
        return materializer
    }

    func makePrimaryAuthService() -> BetterAuthPrimaryAuthService {
        if let cachedPrimaryAuthService { return cachedPrimaryAuthService }
        let service = BetterAuthPrimaryAuthService(context: context,
                                                   relay: makeRelay(),
                                                   materializer: makeMaterializer())
        cachedPrimaryAuthService = service
        return service
    }

    func makeProfileService() -> BetterAuthProfileService {
        if let cachedProfileService { return cachedProfileService }
        let service = BetterAuthProfileService(context: context,
                                               relay: makeRelay(),
                                               materializer: makeMaterializer())
        cachedProfileService = service
        return service
    }

    func makePasskeyService() -> BetterAuthPasskeyService {
        if let cachedPasskeyService { return cachedPasskeyService }
        let service = BetterAuthPasskeyService(context: context,
                                               relay: makeRelay(),
                                               materializer: makeMaterializer())
        cachedPasskeyService = service
        return service
    }

    func makeOneTimeCodeService() -> BetterAuthOneTimeCodeService {
        if let cachedOneTimeCodeService { return cachedOneTimeCodeService }
        let service = BetterAuthOneTimeCodeService(context: context,
                                                   relay: makeRelay(),
                                                   materializer: makeMaterializer())
        cachedOneTimeCodeService = service
        return service
    }

    func makeTwoFactorService() -> BetterAuthTwoFactorService {
        if let cachedTwoFactorService { return cachedTwoFactorService }
        let service = BetterAuthTwoFactorService(context: context,
                                                 relay: makeRelay(),
                                                 materializer: makeMaterializer())
        cachedTwoFactorService = service
        return service
    }

    func makeSessionAdministrationService() -> BetterAuthSessionAdministrationService {
        if let cachedSessionAdministrationService { return cachedSessionAdministrationService }
        let service = BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
        cachedSessionAdministrationService = service
        return service
    }

    func makeSessionBootstrapService() -> BetterAuthSessionBootstrapService {
        if let cachedSessionBootstrapService { return cachedSessionBootstrapService }
        let service = BetterAuthSessionBootstrapService(context: context, relay: makeRelay())
        cachedSessionBootstrapService = service
        return service
    }

    func makeOAuthService() -> BetterAuthOAuthService {
        if let cachedOAuthService { return cachedOAuthService }
        let service = BetterAuthOAuthService(context: context, relay: makeRelay())
        cachedOAuthService = service
        return service
    }

    func throttleAuthOperation(_ operation: String) async throws {
        guard let policy = configuration.auth.throttlePolicy else { return }
        try await authThrottle.check(operation: operation, policy: policy)
    }

    public init(configuration: BetterAuthConfiguration,
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
        self.authFlowService = BetterAuthAuthFlowService(configuration: configuration, network: self.network)
        self.userAccountService = BetterAuthUserAccountService(configuration: configuration, network: self.network)
        self.callbackHandler = BetterAuthCallbackHandler(baseURL: configuration.baseURL,
                                                         endpoints: configuration.endpoints,
                                                         callbackURLSchemes: configuration.auth.callbackURLSchemes)
        self.context = BetterAuthSessionContext(configuration: configuration,
                                                state: self.state,
                                                sessionService: self.sessionService,
                                                refreshService: self.refreshService,
                                                authFlowService: self.authFlowService,
                                                userAccountService: self.userAccountService,
                                                callbackHandler: self.callbackHandler,
                                                network: self.network,
                                                logger: logger)
        self.authStateListenerRegistrations = Self.makeAuthStateListenerRegistrations(authStateListeners,
                                                                                      eventEmitter: eventEmitter)
    }

    // MARK: - Event Stream

    public nonisolated var onAuthStateChange: AuthEventEmitter {
        state.eventEmitter
    }

    public nonisolated var authStateChanges: AsyncStream<AuthStateChange> {
        state.stateChanges
    }

    public nonisolated var accessTokenChanges: AsyncStream<String?> {
        AsyncStream { continuation in
            let task = Task {
                for await change in authStateChanges {
                    continuation.yield(change.session?.session.accessToken)
                }
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    public nonisolated var currentAuthState: AuthStateChange? {
        state.latest
    }

    // MARK: - Sign Out

    /// Signs out and clears the local session. Optionally revokes the session on the backend.
    public func signOut(remotely: Bool = true) async throws {
        stopAutoRefresh()
        try await makeSessionAdministrationService().signOut(remotely: remotely,
                                                             accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Auto-Refresh

    public func startAutoRefresh() {
        stopAutoRefresh()
        logger?.debug("Starting auto-refresh timer")
        autoRefreshTask = Task { [weak self] in
            await self?.runAutoRefreshLoop()
        }
    }

    public func stopAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }

    public func shutdown() {
        stopAutoRefresh()
        inFlightRefreshTask?.cancel()
        inFlightRefreshTask = nil
        authStateListenerRegistrations.forEach { $0.remove() }
        authStateListenerRegistrations.removeAll()
    }

    public func applicationDidBecomeActive() async {
        guard configuration.autoRefreshToken, state.currentSession != nil else { return }
        startAutoRefresh()
        do {
            _ = try await refreshSessionIfNeeded()
        } catch {
            logger?.warning("Session refresh on app activation failed: \(error)")
        }
    }

    public func applicationWillResignActive() {
        stopAutoRefresh()
    }

    deinit {
        autoRefreshTask?.cancel()
        inFlightRefreshTask?.cancel()
        authStateListenerRegistrations.forEach { $0.remove() }
    }

    func runAutoRefreshLoop() async {
        while !Task.isCancelled {
            guard let expiresAt = state.currentSession?.session.expiresAt else { return }
            let sleepDuration = max(expiresAt.timeIntervalSinceNow - AutoRefreshConstants.refreshLeadTime,
                                    AutoRefreshConstants.minimumSleepInterval)
            do {
                try await Task.sleep(for: .seconds(sleepDuration))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            logger?.debug("Auto-refreshing session before expiry")
            do {
                _ = try await refreshSession()
            } catch {
                logger?.warning("Automatic session refresh failed: \(error)")
            }
        }
    }

    // MARK: - Deep Link Handling

    public func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        callbackHandler.parseIncomingURL(url)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        switch parseIncomingURL(url) {
        case let .genericOAuth(payload):
            try await .genericOAuth(completeGenericOAuth(payload))

        case let .magicLink(payload):
            try await .magicLink(verifyMagicLink(payload))

        case let .verifyEmail(payload):
            try await .verifyEmail(verifyEmail(payload))

        case .unsupported:
            .ignored
        }
    }

    public func handle(_ url: URL) async {
        do {
            let result = try await handleIncomingURL(url)
            switch result {
            case .genericOAuth:
                logger?.info("OAuth callback handled")

            case let .magicLink(result):
                logger?.info("Magic link callback handled: \(result)")

            case let .verifyEmail(result):
                logger?.info("Verify email callback handled: \(result)")

            case .ignored:
                logger?.warning("Unsupported auth callback URL: \(url)")
            }
        } catch {
            logger?.error("Auth callback failed: \(error)")
        }
    }

    public func installAuthStateListeners(_ listeners: [any BetterAuthAuthStateListener]) async {
        authStateListenerRegistrations.forEach { $0.remove() }
        authStateListenerRegistrations = Self.makeAuthStateListenerRegistrations(listeners,
                                                                                 eventEmitter: state.eventEmitter)
    }

    // MARK: - Session Lifecycle Helpers

    func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent) throws {
        _ = try makeRelay().setSession(session, event: event)
        if session != nil, configuration.autoRefreshToken {
            startAutoRefresh()
        } else if session == nil {
            stopAutoRefresh()
        }
    }

    func clearSession(event: AuthChangeEvent = .signedOut) throws {
        try setSession(nil, event: event)
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

    func updateAutoRefresh(for result: BetterAuthRestoreResult) {
        switch result {
        case let .restored(session, _, _):
            updateAutoRefresh(for: session)

        case .noStoredSession, .cleared:
            updateAutoRefresh(for: nil)
        }
    }
}

struct SignOutResponse: Decodable {
    let success: Bool
}

struct RevokeSessionRequest: Encodable {
    let token: String
}

extension BetterAuthSessionManager: BetterAuthAuthPerforming, BetterAuthSessionProviding, BetterAuthStateObserving {}
