import BetterAuth

public struct BetterAuthAppleSignInEndpoints: Sendable, Equatable {
    public let signInPath: String
    public init(signInPath: String = "/api/auth/apple/native") {
        self.signInPath = signInPath
    }
}

public struct BetterAuthAppleSignInClient: BetterAuthFeatureClient, Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let outcomes: any BetterAuthSessionOutcomeApplying
    private let throttle: any BetterAuthAuthOperationThrottling
    private let endpoints: BetterAuthAppleSignInEndpoints
    init(context: BetterAuthModuleContext, endpoints: BetterAuthAppleSignInEndpoints) {
        requests = context.requestsPerformer
        outcomes = context.sessionOutcomes
        throttle = context.authOperationThrottle
        self.endpoints = endpoints
    }

    public func signIn(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await throttle.checkAuthOperation("apple.sign-in")
        let session: BetterAuthSession = try await requests.sendJSON(path: endpoints.signInPath,
                                                                     body: payload,
                                                                     requiresAuthentication: false,
                                                                     retryOnUnauthorized: false,
                                                                     allowsTransientRetry: false)
        return try await outcomes.applySessionOutcome(.signedIn(session))
    }
}

public struct BetterAuthAppleSignInModule: BetterAuthModule {
    public static let identifier = "apple-sign-in"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthAppleSignInEndpoints
    public init(endpoints: BetterAuthAppleSignInEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        Runtime(client: .init(context: context, endpoints: endpoints))
    }

    public struct Runtime: BetterAuthModuleRuntime {
        public let moduleIdentifier = BetterAuthAppleSignInModule.identifier
        public let client: BetterAuthAppleSignInClient
    }
}

public extension BetterAuthModuleSupporting {
    func requireAppleSignIn() throws -> BetterAuthAppleSignInClient {
        guard let runtime = moduleRuntime(for: BetterAuthAppleSignInModule.identifier,
                                          as: BetterAuthAppleSignInModule.Runtime.self)
        else {
            throw BetterAuthModuleNotRegisteredError(identifier: BetterAuthAppleSignInModule.identifier)
        }
        return runtime.client
    }
}
