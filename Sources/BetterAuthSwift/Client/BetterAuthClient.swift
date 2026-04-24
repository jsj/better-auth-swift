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
    /// Session manager for sign-in, sign-out, refresh, and all auth flows.
    public let auth: BetterAuthSessionManager
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
        self.configuration = configuration
        let resolvedStore = sessionStore ?? KeychainSessionStore(service: configuration.storage.service,
                                                                 accessGroup: configuration.storage.accessGroup,
                                                                 accessibility: configuration.storage.accessibility,
                                                                 synchronizable: configuration.storage.synchronizable)
        let auth = BetterAuthSessionManager(configuration: configuration,
                                            sessionStore: resolvedStore,
                                            transport: transport,
                                            logger: configuration.logger,
                                            eventEmitter: eventEmitter,
                                            authStateListeners: [])
        self.auth = auth
        let baseRequests = BetterAuthRequestClient(configuration: configuration,
                                                   sessionManager: auth,
                                                   transport: transport)
        let resolvedModules = BetterAuthModuleRegistry.build(configuration: configuration,
                                                             authLifecycle: auth,
                                                             requestsPerformer: baseRequests,
                                                             modules: modules)
        self.modules = resolvedModules
        if resolvedModules.registeredRequestHooks.isEmpty {
            self.requests = baseRequests
        } else {
            self.requests = BetterAuthRequestClient(configuration: configuration,
                                                    sessionManager: auth,
                                                    transport: transport,
                                                    requestHooks: resolvedModules.registeredRequestHooks)
        }
        self.authStateListenerRegistrations = resolvedModules.registeredAuthStateListeners.map { listener in
            auth.onAuthStateChange.on { change in
                await listener.authStateDidChange(change)
            }
        }
    }
}

public extension BetterAuthClient {
    var authLifecycle: any BetterAuthAuthPerforming {
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
