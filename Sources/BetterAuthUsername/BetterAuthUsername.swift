import BetterAuth

public struct BetterAuthUsernameEndpoints: Sendable, Equatable {
    public let availabilityPath: String
    public let signInPath: String
    public init(availabilityPath: String = "/api/auth/is-username-available",
                signInPath: String = "/api/auth/sign-in/username")
    {
        self.availabilityPath = availabilityPath
        self.signInPath = signInPath
    }
}

public struct BetterAuthUsernameClient: BetterAuthFeatureClient, Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let outcomes: any BetterAuthSessionOutcomeApplying
    private let throttle: any BetterAuthAuthOperationThrottling
    private let endpoints: BetterAuthUsernameEndpoints
    init(context: BetterAuthModuleContext, endpoints: BetterAuthUsernameEndpoints) {
        requests = context.requestsPerformer
        outcomes = context.sessionOutcomes
        throttle = context.authOperationThrottle
        self.endpoints = endpoints
    }

    public func isAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await throttle.checkAuthOperation("username.availability")
        let response: UsernameAvailabilityResponse = try await requests.sendJSON(path: endpoints.availabilityPath,
                                                                                 body: payload,
                                                                                 requiresAuthentication: false,
                                                                                 retryOnUnauthorized: false)
        return response.available
    }

    public func signIn(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await throttle.checkAuthOperation("username.sign-in")
        let session: BetterAuthSession = try await requests.sendJSON(path: endpoints.signInPath,
                                                                     body: payload,
                                                                     requiresAuthentication: false,
                                                                     retryOnUnauthorized: false,
                                                                     allowsTransientRetry: false)
        return try await outcomes.applySessionOutcome(.signedIn(session))
    }
}

public struct BetterAuthUsernameModule: BetterAuthModule {
    public static let identifier = "username"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthUsernameEndpoints
    public init(endpoints: BetterAuthUsernameEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        Runtime(client: .init(context: context, endpoints: endpoints))
    }

    public struct Runtime: BetterAuthModuleRuntime {
        public let moduleIdentifier = BetterAuthUsernameModule.identifier
        public let client: BetterAuthUsernameClient
    }
}

public extension BetterAuthModuleSupporting {
    func requireUsername() throws -> BetterAuthUsernameClient {
        guard let runtime = moduleRuntime(for: BetterAuthUsernameModule.identifier,
                                          as: BetterAuthUsernameModule.Runtime.self)
        else {
            throw BetterAuthModuleNotRegisteredError(identifier: BetterAuthUsernameModule.identifier)
        }
        return runtime.client
    }
}
