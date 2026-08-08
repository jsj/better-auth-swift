import BetterAuth

public struct BetterAuthAnonymousEndpoints: Sendable, Equatable {
    public let signInPath: String
    public let deleteUserPath: String
    public init(signInPath: String = "/api/auth/sign-in/anonymous",
                deleteUserPath: String = "/api/auth/delete-anonymous-user")
    {
        self.signInPath = signInPath
        self.deleteUserPath = deleteUserPath
    }
}

public struct BetterAuthAnonymousClient: BetterAuthFeatureClient, Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let outcomes: any BetterAuthSessionOutcomeApplying
    private let throttle: any BetterAuthAuthOperationThrottling
    private let lifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching
    private let endpoints: BetterAuthAnonymousEndpoints
    init(context: BetterAuthModuleContext, endpoints: BetterAuthAnonymousEndpoints) {
        requests = context.requestsPerformer
        outcomes = context.sessionOutcomes
        throttle = context.authOperationThrottle
        lifecycle = context.authSessionLifecycle
        self.endpoints = endpoints
    }

    public func signIn() async throws -> BetterAuthSession {
        try await throttle.checkAuthOperation("anonymous.sign-in")
        let response: AnonymousSignInResponse = try await requests.sendJSON(path: endpoints.signInPath,
                                                                            method: "POST",
                                                                            body: EmptyRequest(),
                                                                            requiresAuthentication: false,
                                                                            retryOnUnauthorized: false,
                                                                            allowsTransientRetry: false)
        return try await outcomes.applySessionOutcome(.token(response.token, fallbackUser: response.user))
    }

    public func deleteUser() async throws -> Bool {
        try await throttle.checkAuthOperation("anonymous.delete")
        let response: BetterAuthStatusResponse = try await requests.sendJSON(path: endpoints.deleteUserPath,
                                                                             method: "POST",
                                                                             body: EmptyRequest())
        if response.status {
            try await lifecycle.signOut(remotely: false)
        }
        return response.status
    }
}

private struct EmptyRequest: Encodable {}
private struct AnonymousSignInResponse: Decodable {
    let token: String
    let user: BetterAuthSession.User
}

public struct BetterAuthAnonymousModule: BetterAuthModule {
    public static let identifier = "anonymous"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthAnonymousEndpoints
    public init(endpoints: BetterAuthAnonymousEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        Runtime(client: .init(context: context, endpoints: endpoints))
    }

    public struct Runtime: BetterAuthModuleRuntime {
        public let moduleIdentifier = BetterAuthAnonymousModule.identifier
        public let client: BetterAuthAnonymousClient
    }
}

public extension BetterAuthModuleSupporting {
    func requireAnonymous() throws -> BetterAuthAnonymousClient {
        guard let runtime = moduleRuntime(for: BetterAuthAnonymousModule.identifier,
                                          as: BetterAuthAnonymousModule.Runtime.self)
        else {
            throw BetterAuthModuleNotRegisteredError(identifier: BetterAuthAnonymousModule.identifier)
        }
        return runtime.client
    }
}
