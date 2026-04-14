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
public struct BetterAuthClient: Sendable {
    /// The resolved configuration for this client.
    public let configuration: BetterAuthConfiguration
    /// Session manager for sign-in, sign-out, refresh, and all auth flows.
    public let auth: BetterAuthSessionManager
    /// Authenticated HTTP request client with automatic 401 retry.
    public let requests: BetterAuthRequestClient

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
                eventEmitter: AuthEventEmitter = AuthEventEmitter())
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
                                            eventEmitter: eventEmitter)
        self.auth = auth
        self.requests = BetterAuthRequestClient(configuration: configuration,
                                                sessionManager: auth,
                                                transport: transport)
    }
}

public extension BetterAuthClient {
    /// Convenience initializer that builds a configuration from individual parameters.
    init(baseURL: URL,
         storage: BetterAuthConfiguration.SessionStorage = .init(),
         endpoints: BetterAuthConfiguration.Endpoints = .init(),
         auth: BetterAuthConfiguration.Auth = .init(),
         networking: BetterAuthConfiguration.Networking = .init(),
         clockSkew: TimeInterval? = nil,
         autoRefreshToken: Bool? = nil,
         retryPolicy: RetryPolicy? = nil,
         requestOrigin: String? = nil,
         logger: BetterAuthLogger? = nil,
         sessionStore: BetterAuthSessionStore? = nil,
         transport: BetterAuthTransport = URLSessionTransport(),
         eventEmitter: AuthEventEmitter = AuthEventEmitter())
    {
        self.init(configuration: BetterAuthConfiguration(baseURL: baseURL,
                                                         storage: storage,
                                                         endpoints: endpoints,
                                                         auth: auth,
                                                         networking: networking,
                                                         clockSkew: clockSkew,
                                                         autoRefreshToken: autoRefreshToken,
                                                         retryPolicy: retryPolicy,
                                                         requestOrigin: requestOrigin,
                                                         logger: logger),
                  sessionStore: sessionStore,
                  transport: transport,
                  eventEmitter: eventEmitter)
    }

    /// Alias for ``auth``.
    var sessionManager: BetterAuthSessionManager {
        auth
    }

    /// Shortcut to the auth event emitter for observing sign-in/sign-out events.
    var onAuthStateChange: AuthEventEmitter {
        auth.onAuthStateChange
    }

    /// Async stream of auth state changes, yielding the latest event to new subscribers.
    var authStateChanges: AsyncStream<AuthStateChange> {
        auth.authStateChanges
    }
}
