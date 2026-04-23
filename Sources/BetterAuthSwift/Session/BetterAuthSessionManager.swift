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
    var authStateListenerRegistrations: [any AuthStateChangeRegistration] = []
    var inFlightRefreshTask: Task<BetterAuthSession, Error>?
    var autoRefreshTask: Task<Void, Never>?

    var context: BetterAuthSessionContext {
        BetterAuthSessionContext(configuration: configuration,
                                 state: state,
                                 sessionService: sessionService,
                                 refreshService: refreshService,
                                 authFlowService: authFlowService,
                                 userAccountService: userAccountService,
                                 callbackHandler: callbackHandler,
                                 network: network,
                                 logger: logger)
    }

    func makeRelay() -> BetterAuthSessionEventRelay {
        BetterAuthSessionEventRelay(context: context,
                                    refreshSession: {
                                        try await self.refreshSession()
                                    })
    }

    func makeMaterializer() -> BetterAuthSessionMaterializer {
        BetterAuthSessionMaterializer(context: context)
    }

    func makePrimaryAuthService() -> BetterAuthPrimaryAuthService {
        BetterAuthPrimaryAuthService(context: context,
                                     relay: makeRelay(),
                                     materializer: makeMaterializer())
    }

    func makeProfileService() -> BetterAuthProfileService {
        BetterAuthProfileService(context: context,
                                 relay: makeRelay(),
                                 materializer: makeMaterializer())
    }

    func makePasskeyService() -> BetterAuthPasskeyService {
        BetterAuthPasskeyService(context: context,
                                 relay: makeRelay(),
                                 materializer: makeMaterializer())
    }

    func makeOneTimeCodeService() -> BetterAuthOneTimeCodeService {
        BetterAuthOneTimeCodeService(context: context,
                                     relay: makeRelay(),
                                     materializer: makeMaterializer())
    }

    func makeTwoFactorService() -> BetterAuthTwoFactorService {
        BetterAuthTwoFactorService(context: context,
                                   relay: makeRelay(),
                                   materializer: makeMaterializer())
    }

    func makeSessionAdministrationService() -> BetterAuthSessionAdministrationService {
        BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
    }

    func makeSessionBootstrapService() -> BetterAuthSessionBootstrapService {
        BetterAuthSessionBootstrapService(context: context, relay: makeRelay())
    }

    func makeOAuthService() -> BetterAuthOAuthService {
        BetterAuthOAuthService(context: context, relay: makeRelay())
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
        self.callbackHandler = BetterAuthCallbackHandler(endpoints: configuration.endpoints)
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
            _ = try? await refreshSession()
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
            case let .genericOAuth(session):
                logger?.info("OAuth callback handled for session: \(session.session.id)")

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

        @unknown default:
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
