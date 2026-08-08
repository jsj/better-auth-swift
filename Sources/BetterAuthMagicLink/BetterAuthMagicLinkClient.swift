import BetterAuth
import Foundation

public struct BetterAuthMagicLinkEndpoints: Sendable, Equatable {
    public let requestPath: String
    public let verifyPath: String

    public init(requestPath: String = "/api/auth/sign-in/magic-link",
                verifyPath: String = "/api/auth/magic-link/verify")
    {
        self.requestPath = requestPath
        self.verifyPath = verifyPath
    }
}

public struct BetterAuthMagicLinkClient: Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let sessionOutcomes: any BetterAuthSessionOutcomeApplying
    private let endpoints: BetterAuthMagicLinkEndpoints
    private let baseURL: URL
    private let acceptedURLSchemes: Set<String>
    private let operationThrottle: any BetterAuthAuthOperationThrottling

    init(context: BetterAuthModuleContext, endpoints: BetterAuthMagicLinkEndpoints) {
        requests = context.requestsPerformer
        sessionOutcomes = context.sessionOutcomes
        self.endpoints = endpoints
        baseURL = context.configuration.baseURL
        var schemes = context.configuration.auth.callbackURLSchemes
        if let baseScheme = context.configuration.baseURL.scheme?.lowercased() {
            schemes.insert(baseScheme)
        }
        acceptedURLSchemes = schemes
        operationThrottle = context.authOperationThrottle
    }

    @discardableResult
    public func request(_ payload: MagicLinkRequest) async throws -> Bool {
        try await operationThrottle.checkAuthOperation("magic-link.request")
        let response: StatusResponse = try await requests.sendJSON(path: endpoints.requestPath,
                                                                   body: payload,
                                                                   requiresAuthentication: false,
                                                                   retryOnUnauthorized: false,
                                                                   allowsTransientRetry: false)
        guard let status = response.status ?? response.success else {
            throw BetterAuthError.invalidResponse
        }
        return status
    }

    @discardableResult
    public func verify(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await operationThrottle.checkAuthOperation("magic-link.verify")
        let response: VerificationResponse = try await requests.sendJSON(path: try verificationPath(for: payload),
                                                                         requiresAuthentication: false,
                                                                         retryOnUnauthorized: false)
        if let failure = response.failure {
            return .failure(failure)
        }
        let session: BetterAuthSession
        if let decodedSession = response.session {
            session = try await sessionOutcomes.applySessionOutcome(.signedIn(decodedSession))
        } else if let token = response.token, let user = response.user {
            session = try await sessionOutcomes.applySessionOutcome(.token(token, fallbackUser: user))
        } else {
            throw BetterAuthError.invalidResponse
        }
        return .signedIn(session)
    }

    public func verificationRequest(from url: URL) -> MagicLinkVerifyRequest? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let scheme = components.scheme?.lowercased(),
              acceptedURLSchemes.contains(scheme),
              isTrustedOrigin(components),
              components.path == endpoints.verifyPath,
              let token = components.queryItems?.first(where: { $0.name == "token" })?.value
        else {
            return nil
        }
        return MagicLinkVerifyRequest(token: token,
                                      callbackURL: value(named: "callbackURL", in: components),
                                      newUserCallbackURL: value(named: "newUserCallbackURL", in: components),
                                      errorCallbackURL: value(named: "errorCallbackURL", in: components))
    }

    @discardableResult
    public func handleIncomingURL(_ url: URL) async throws -> MagicLinkVerificationResult? {
        guard let payload = verificationRequest(from: url) else { return nil }
        return try await verify(payload)
    }

    private func verificationPath(for payload: MagicLinkVerifyRequest) throws -> String {
        var components = URLComponents()
        components.path = endpoints.verifyPath
        components.queryItems = [URLQueryItem(name: "token", value: payload.token),
                                 URLQueryItem(name: "callbackURL", value: payload.callbackURL),
                                 URLQueryItem(name: "newUserCallbackURL", value: payload.newUserCallbackURL),
                                 URLQueryItem(name: "errorCallbackURL", value: payload.errorCallbackURL)]
        guard let path = components.string else {
            throw BetterAuthError.invalidURL
        }
        return path
    }

    private func value(named name: String, in components: URLComponents) -> String? {
        components.queryItems?.first(where: { $0.name == name })?.value
    }

    private func isTrustedOrigin(_ components: URLComponents) -> Bool {
        guard components.scheme == "http" || components.scheme == "https" else {
            return true
        }
        guard let url = components.url else { return false }
        return url.scheme?.lowercased() == baseURL.scheme?.lowercased() &&
            url.host?.lowercased() == baseURL.host?.lowercased() &&
            normalizedPort(url) == normalizedPort(baseURL)
    }

    private func normalizedPort(_ url: URL) -> Int? {
        if let port = url.port {
            return port
        }
        return url.scheme?.lowercased() == "https" ? 443 : 80
    }
}

private struct StatusResponse: Decodable {
    let status: Bool?
    let success: Bool?
}

private struct VerificationResponse: Decodable {
    let token: String?
    let user: BetterAuthSession.User?
    let session: BetterAuthSession?
    let failure: MagicLinkFailure?

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            token = session.session.accessToken
            user = session.user
            self.session = session
            failure = nil
            return
        }
        if let response = try? container.decode(ResponseEnvelope.self),
           response.token != nil || response.user != nil || response.session != nil
        {
            token = response.token
            user = response.user
            session = response.session
            failure = nil
            return
        }
        token = nil
        user = nil
        session = nil
        failure = try container.decode(MagicLinkFailure.self)
    }

    private struct ResponseEnvelope: Decodable {
        let token: String?
        let user: BetterAuthSession.User?
        let session: BetterAuthSession?
    }
}
