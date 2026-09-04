import BetterAuth
import Foundation

public struct BetterAuthSocialOAuthEndpoints: Sendable, Equatable {
    public let socialSignInPath: String
    public let genericSignInPath: String
    public let genericLinkPath: String
    public let genericCallbackPath: String
    public let linkedAccountsPath: String
    public let linkAccountPath: String

    public init(socialSignInPath: String = "/api/auth/sign-in/social",
                genericSignInPath: String = "/api/auth/sign-in/oauth2",
                genericLinkPath: String = "/api/auth/oauth2/link",
                genericCallbackPath: String = "/api/auth/oauth2/callback/{providerId}",
                linkedAccountsPath: String = "/api/auth/list-accounts",
                linkAccountPath: String = "/api/auth/link-social")
    {
        self.socialSignInPath = socialSignInPath
        self.genericSignInPath = genericSignInPath
        self.genericLinkPath = genericLinkPath
        self.genericCallbackPath = genericCallbackPath
        self.linkedAccountsPath = linkedAccountsPath
        self.linkAccountPath = linkAccountPath
    }
}

public struct BetterAuthSocialOAuthClient: BetterAuthFeatureClient, Sendable {
    private let requests: any BetterAuthRequestPerforming
    private let outcomes: any BetterAuthSessionOutcomeApplying
    private let throttle: any BetterAuthAuthOperationThrottling
    private let lifecycle: any BetterAuthSessionLifecycle
    private let endpoints: BetterAuthSocialOAuthEndpoints
    private let baseURL: URL
    private let callbackURLSchemes: Set<String>
    init(context: BetterAuthModuleContext, endpoints: BetterAuthSocialOAuthEndpoints) {
        requests = context.requestsPerformer
        outcomes = context.sessionOutcomes
        throttle = context.authOperationThrottle
        lifecycle = context.authSessionLifecycle
        self.endpoints = endpoints
        baseURL = context.configuration.baseURL
        callbackURLSchemes = context.configuration.auth.callbackURLSchemes
    }

    public func signIn(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await throttle.checkAuthOperation("social-oauth.sign-in")
        let response: SocialSignInTransportResponse = try await requests.sendJSON(path: endpoints.socialSignInPath,
                                                                                  body: payload,
                                                                                  requiresAuthentication: false,
                                                                                  retryOnUnauthorized: false,
                                                                                  allowsTransientRetry: false)
        if let session = response.materializedSession {
            _ = try await outcomes.applySessionOutcome(.signedIn(session))
            return .signedIn(.init(redirect: response.redirect,
                                   token: session.session.accessToken,
                                   url: response.url,
                                   user: session.user))
        }
        if let signedIn = response.signedIn {
            _ = try await outcomes.applySessionOutcome(.token(signedIn.token, fallbackUser: signedIn.user))
            return .signedIn(signedIn)
        }
        return .authorizationURL(try response.authorizationURL.get())
    }

    public func begin(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await throttle.checkAuthOperation("social-oauth.begin")
        return try await requests.sendJSON(path: endpoints.genericSignInPath,
                                           body: payload,
                                           requiresAuthentication: false,
                                           retryOnUnauthorized: false)
    }

    public func link(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await throttle.checkAuthOperation("social-oauth.link")
        return try await requests.sendJSON(path: endpoints.genericLinkPath, body: payload)
    }

    public func complete(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await throttle.checkAuthOperation("social-oauth.complete")
        let hasSession = await lifecycle.currentSession() != nil
        let session: BetterAuthSession = try await requests.sendJSON(path: callbackPath(for: payload),
                                                                     requiresAuthentication: hasSession,
                                                                     retryOnUnauthorized: false,
                                                                     allowsTransientRetry: false)
        return try await outcomes.applySessionOutcome(.signedIn(session))
    }

    public func parseIncomingURL(_ url: URL) -> GenericOAuthCallbackRequest? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              acceptsURLScheme(components.scheme),
              let providerID = providerID(from: components.path),
              let code = components.queryItems?.first(where: { $0.name == "code" })?.value,
              let state = components.queryItems?.first(where: { $0.name == "state" })?.value
        else {
            return nil
        }
        let issuer = components.queryItems?.first(where: { $0.name == "iss" })?.value
        return .init(providerId: providerID, code: code, state: state, issuer: issuer)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthSession {
        guard let payload = parseIncomingURL(url) else {
            throw BetterAuthError.invalidResponse
        }
        return try await complete(payload)
    }

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await requests.sendJSON(path: endpoints.linkedAccountsPath)
    }

    public func linkAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await throttle.checkAuthOperation("social-oauth.link-account")
        return try await requests.sendJSON(path: endpoints.linkAccountPath,
                                           body: payload,
                                           retryOnUnauthorized: false)
    }

    private func callbackPath(for payload: GenericOAuthCallbackRequest) -> String {
        var components = URLComponents()
        components.path = endpoints.genericCallbackPath.replacingOccurrences(of: "{providerId}",
                                                                             with: payload.providerId)
        components.queryItems = [URLQueryItem(name: "code", value: payload.code),
                                 URLQueryItem(name: "state", value: payload.state)]
        if let issuer = payload.issuer {
            components.queryItems?.append(.init(name: "iss", value: issuer))
        }
        return components.string ?? components.path
    }

    private func acceptsURLScheme(_ scheme: String?) -> Bool {
        guard let scheme = scheme?.lowercased() else { return false }
        var allowed = callbackURLSchemes
        if let baseScheme = baseURL.scheme?.lowercased() {
            allowed.insert(baseScheme)
        }
        return allowed.contains(scheme)
    }

    private func providerID(from path: String) -> String? {
        let placeholder = "{providerId}"
        guard let range = endpoints.genericCallbackPath.range(of: placeholder) else { return nil }
        let prefix = String(endpoints.genericCallbackPath[..<range.lowerBound])
        let suffix = String(endpoints.genericCallbackPath[range.upperBound...])
        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else { return nil }
        let start = path.index(path.startIndex, offsetBy: prefix.count)
        let end = path.index(path.endIndex, offsetBy: -suffix.count)
        guard start < end else { return nil }
        let value = String(path[start ..< end])
        return value.removingPercentEncoding ?? value
    }
}

public struct BetterAuthSocialOAuthModule: BetterAuthModule {
    public static let identifier = "social-oauth"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthSocialOAuthEndpoints
    public init(endpoints: BetterAuthSocialOAuthEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        Runtime(client: .init(context: context, endpoints: endpoints))
    }

    public struct Runtime: BetterAuthModuleRuntime {
        public let moduleIdentifier = BetterAuthSocialOAuthModule.identifier
        public let client: BetterAuthSocialOAuthClient
    }
}

public extension BetterAuthModuleSupporting {
    func requireSocialOAuth() throws -> BetterAuthSocialOAuthClient {
        guard let runtime = moduleRuntime(for: BetterAuthSocialOAuthModule.identifier,
                                          as: BetterAuthSocialOAuthModule.Runtime.self)
        else {
            throw BetterAuthModuleNotRegisteredError(identifier: BetterAuthSocialOAuthModule.identifier)
        }
        return runtime.client
    }
}
