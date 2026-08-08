import Foundation

/// The main entry point for the Better Auth Swift SDK.
///
/// Create a single shared instance for your app and use ``auth`` for
/// authentication flows and ``requests`` for authenticated HTTP calls.
///
/// ```swift
/// let client = BetterAuthClient(
///     baseURL: URL(string: "https://your-api.example.com")!
/// )
/// ```
public struct BetterAuthClient: BetterAuthModuleSupporting, Sendable {
    /// The resolved configuration for this client.
    public let configuration: BetterAuthConfiguration
    /// Auth client for sign-in, sign-out, refresh, and all auth flows.
    public let auth: BetterAuthAuthClient
    /// Authenticated HTTP request client with automatic 401 retry.
    public let requests: BetterAuthRequestClient
    /// Registered optional modules for this client instance.
    public let modules: BetterAuthModuleRegistry
    private let authStateListenerRegistrations: [any AuthStateChangeRegistration]

    /// Creates a client from a full configuration object.
    ///
    /// - Parameters:
    ///   - configuration: The resolved ``BetterAuthConfiguration``.
    ///   - sessionStore: Optional custom session store. Defaults to keychain.
    ///   - transport: HTTP transport layer. Defaults to `URLSession`.
    ///   - eventEmitter: Event emitter for auth state changes.
    public init(configuration: BetterAuthConfiguration,
                sessionStore: BetterAuthSessionStore? = nil,
                transport: BetterAuthTransport = URLSessionTransport(),
                eventEmitter: AuthEventEmitter = AuthEventEmitter(),
                modules: [any BetterAuthModule] = [])
    {
        do {
            try BetterAuthModuleRegistry.validate(modules)
        } catch {
            preconditionFailure(String(describing: error))
        }
        self.configuration = configuration
        let resolvedStore = sessionStore ?? Self.makeSessionStore(storage: configuration.storage)
        let sessionManager = BetterAuthSessionManager(configuration: configuration,
                                                      sessionStore: resolvedStore,
                                                      transport: transport,
                                                      logger: configuration.logger,
                                                      eventEmitter: eventEmitter,
                                                      authStateListeners: [])
        let auth = BetterAuthAuthClient(sessionManager: sessionManager)
        self.auth = auth
        let baseRequests = BetterAuthRequestClient(configuration: configuration,
                                                   sessionManager: sessionManager,
                                                   transport: transport)
        let resolvedModules = BetterAuthModuleRegistry.build(configuration: configuration,
                                                             authFeatures: BetterAuthAuthFeatures(sessionLifecycle: auth,
                                                                                                  sessionOutcomes: auth,
                                                                                                  primaryAuth: auth,
                                                                                                  oauthAuth: auth,
                                                                                                  oneTimeCodeAuth: auth,
                                                                                                  twoFactorAuth: auth,
                                                                                                  passkeyAuth: auth,
                                                                                                  accountAuth: auth,
                                                                                                  sessionAdministration: auth),
                                                             requestsPerformer: baseRequests,
                                                             requestPerformerFactory: { hooks in
                                                                 BetterAuthRequestClient(configuration: configuration,
                                                                                         sessionManager: sessionManager,
                                                                                         transport: transport,
                                                                                         requestHooks: hooks)
                                                             },
                                                             modules: modules)
        self.modules = resolvedModules
        if resolvedModules.registeredRequestHooks.isEmpty {
            self.requests = baseRequests
        } else {
            self.requests = BetterAuthRequestClient(configuration: configuration,
                                                    sessionManager: sessionManager,
                                                    transport: transport,
                                                    requestHooks: resolvedModules.registeredRequestHooks)
        }
        self.authStateListenerRegistrations = resolvedModules.registeredAuthStateListeners.map { listener in
            sessionManager.onAuthStateChange.on { change in
                await listener.authStateDidChange(change)
            }
        }
    }

    private static func makeSessionStore(storage: BetterAuthConfiguration
        .SessionStorage) -> any BetterAuthSessionStore
    {
        let primaryStore = KeychainSessionStore(service: storage.service,
                                                accessGroup: storage.accessGroup,
                                                accessibility: storage.accessibility,
                                                synchronizable: storage.synchronizable)
        guard storage.synchronizable, storage.migratesFromNonSynchronizableKeychain else {
            return primaryStore
        }

        let localStore = KeychainSessionStore(service: storage.service,
                                              accessGroup: storage.accessGroup,
                                              accessibility: storage.accessibility,
                                              synchronizable: false)
        return MigratingSessionStore(primary: primaryStore, legacyStores: [localStore])
    }
}

public extension BetterAuthClient {
    var authSessionLifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching {
        auth
    }

    var primaryAuth: any BetterAuthPrimaryAuthPerforming {
        auth
    }

    var oauthAuth: any BetterAuthOAuthPerforming {
        auth
    }

    var oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming {
        auth
    }

    var twoFactorAuth: any BetterAuthTwoFactorPerforming {
        auth
    }

    var passkeyAuth: any BetterAuthPasskeyPerforming {
        auth
    }

    var accountAuth: any BetterAuthAccountPerforming {
        auth
    }

    var sessionAdministration: any BetterAuthSessionAdministrating {
        auth
    }

    var requestsPerformer: any BetterAuthRequestPerforming {
        requests
    }

    /// Convenience initializer that builds a configuration from individual parameters.
    init(baseURL: URL,
         storage: BetterAuthConfiguration.SessionStorage = .init(),
         endpoints: BetterAuthConfiguration.Endpoints = .init(),
         auth: BetterAuthConfiguration.Auth = .init(),
         networking: BetterAuthConfiguration.Networking = .init(),
         clockSkew: TimeInterval? = nil,
         autoRefreshToken: Bool? = nil,
         authThrottlePolicy: BetterAuthConfiguration.AuthThrottlePolicy? = nil,
         callbackURLSchemes: Set<String>? = nil,
         retryPolicy: RetryPolicy? = nil,
         requestOrigin: String? = nil,
         logger: BetterAuthLogger? = nil,
         sessionStore: BetterAuthSessionStore? = nil,
         transport: BetterAuthTransport = URLSessionTransport(),
         eventEmitter: AuthEventEmitter = AuthEventEmitter(),
         modules: [any BetterAuthModule] = [])
    {
        self.init(configuration: BetterAuthConfiguration(baseURL: baseURL,
                                                         storage: storage,
                                                         endpoints: endpoints,
                                                         auth: auth,
                                                         networking: networking,
                                                         clockSkew: clockSkew,
                                                         autoRefreshToken: autoRefreshToken,
                                                         authThrottlePolicy: authThrottlePolicy,
                                                         callbackURLSchemes: callbackURLSchemes,
                                                         retryPolicy: retryPolicy,
                                                         requestOrigin: requestOrigin,
                                                         logger: logger),
                  sessionStore: sessionStore,
                  transport: transport,
                  eventEmitter: eventEmitter,
                  modules: modules)
    }
}
