import BetterAuth

public struct BetterAuthEmailPasswordEndpoints: Sendable, Equatable {
    public let signUpPath: String
    public let signInPath: String
    public let forgotPasswordPath: String
    public let resetPasswordPath: String

    public init(signUpPath: String = "/api/auth/email/sign-up",
                signInPath: String = "/api/auth/email/sign-in",
                forgotPasswordPath: String = "/api/auth/forget-password",
                resetPasswordPath: String = "/api/auth/reset-password")
    {
        self.signUpPath = signUpPath
        self.signInPath = signInPath
        self.forgotPasswordPath = forgotPasswordPath
        self.resetPasswordPath = resetPasswordPath
    }
}

public struct BetterAuthEmailPasswordClient: BetterAuthFeatureClient, Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let sessionOutcomes: any BetterAuthSessionOutcomeApplying
    private let throttle: any BetterAuthAuthOperationThrottling
    private let sessions: any BetterAuthSessionAdministrating
    private let lifecycle: any BetterAuthSessionLifecycle
    private let endpoints: BetterAuthEmailPasswordEndpoints

    init(context: BetterAuthModuleContext, endpoints: BetterAuthEmailPasswordEndpoints) {
        requests = context.requestsPerformer
        sessionOutcomes = context.sessionOutcomes
        throttle = context.authOperationThrottle
        sessions = context.sessionAdministration
        lifecycle = context.authSessionLifecycle
        self.endpoints = endpoints
    }

    public func signUp(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await throttle.checkAuthOperation("email-password.sign-up")
        let result: EmailSignUpResult = try await requests.sendJSON(path: endpoints.signUpPath,
                                                                    body: payload,
                                                                    requiresAuthentication: false,
                                                                    retryOnUnauthorized: false,
                                                                    allowsTransientRetry: false)
        if case let .signedIn(session) = result {
            _ = try await sessionOutcomes.applySessionOutcome(.signedIn(session))
        }
        return result
    }

    public func signIn(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await throttle.checkAuthOperation("email-password.sign-in")
        let session: BetterAuthSession = try await requests.sendJSON(path: endpoints.signInPath,
                                                                     body: payload,
                                                                     requiresAuthentication: false,
                                                                     retryOnUnauthorized: false,
                                                                     allowsTransientRetry: false)
        return try await sessionOutcomes.applySessionOutcome(.signedIn(session))
    }

    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await throttle.checkAuthOperation("email-password.request-reset")
        let response: BetterAuthStatusResponse = try await requests.sendJSON(path: endpoints.forgotPasswordPath,
                                                                             body: payload,
                                                                             requiresAuthentication: false,
                                                                             retryOnUnauthorized: false,
                                                                             allowsTransientRetry: false)
        return response.status
    }

    public func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await throttle.checkAuthOperation("email-password.reset")
        let response: BetterAuthStatusResponse = try await requests.sendJSON(path: endpoints.resetPasswordPath,
                                                                             body: payload,
                                                                             requiresAuthentication: false,
                                                                             retryOnUnauthorized: false,
                                                                             allowsTransientRetry: false)
        return response.status
    }

    /// Verifies the current user's password without replacing the active session.
    public func reauthenticate(password: String) async throws -> Bool {
        try await throttle.checkAuthOperation("email-password.reauthenticate")
        guard let current = await lifecycle.currentSession(),
              let email = current.user.email
        else {
            throw BetterAuthError.missingSession
        }

        let temporary: BetterAuthSession = try await requests.sendJSON(path: endpoints.signInPath,
                                                                       body: EmailSignInRequest(email: email,
                                                                                                password: password),
                                                                       requiresAuthentication: false,
                                                                       retryOnUnauthorized: false,
                                                                       allowsTransientRetry: false)
        return try await sessions.revokeSession(token: temporary.session.accessToken)
    }
}

public struct BetterAuthEmailPasswordModule: BetterAuthModule {
    public static let identifier = "email-password"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthEmailPasswordEndpoints
    public init(endpoints: BetterAuthEmailPasswordEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        Runtime(client: .init(context: context, endpoints: endpoints))
    }

    public struct Runtime: BetterAuthModuleRuntime {
        public let moduleIdentifier = BetterAuthEmailPasswordModule.identifier
        public let client: BetterAuthEmailPasswordClient
    }
}

public extension BetterAuthModuleSupporting {
    func requireEmailPassword() throws -> BetterAuthEmailPasswordClient {
        guard let runtime = moduleRuntime(for: BetterAuthEmailPasswordModule.identifier,
                                          as: BetterAuthEmailPasswordModule.Runtime.self)
        else {
            throw BetterAuthModuleNotRegisteredError(identifier: BetterAuthEmailPasswordModule.identifier)
        }
        return runtime.client
    }
}
