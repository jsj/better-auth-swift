import Foundation

struct BetterAuthCallbackHandler: Sendable {
    let endpoints: BetterAuthConfiguration.Endpoints

    func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            return .unsupported
        }

        let path = components.path
        let queryItems = components.queryItems ?? []

        if let code = queryItems.first(where: { $0.name == "code" })?.value,
           let state = queryItems.first(where: { $0.name == "state" })?.value
        {
            let pathComponents = path.split(separator: "/")
            if let callbackIndex = pathComponents.firstIndex(of: "callback"), callbackIndex + 1 < pathComponents.count {
                let providerId = String(pathComponents[callbackIndex + 1])
                let issuer = queryItems.first(where: { $0.name == "iss" })?.value
                return .genericOAuth(.init(providerId: providerId, code: code, state: state, issuer: issuer))
            }
        }

        if path.hasSuffix(endpoints.magicLinkVerifyPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .magicLink(.init(token: token,
                                    callbackURL: queryItems.first(where: { $0.name == "callbackURL" })?.value,
                                    newUserCallbackURL: queryItems.first(where: { $0.name == "newUserCallbackURL" })?
                                        .value,
                                    errorCallbackURL: queryItems.first(where: { $0.name == "errorCallbackURL" })?
                                        .value))
        }

        if path.hasSuffix(endpoints.verifyEmailPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .verifyEmail(.init(token: token))
        }

        return .unsupported
    }

    func oauthCallbackPath(for payload: GenericOAuthCallbackRequest) -> String {
        var components = URLComponents()
        components.path = "/api/auth/oauth2/callback/\(payload.providerId)"
        components.queryItems = [URLQueryItem(name: "code", value: payload.code),
                                 URLQueryItem(name: "state", value: payload.state)]
        if let issuer = payload.issuer {
            components.queryItems?.append(URLQueryItem(name: "iss", value: issuer))
        }
        return components.string ?? "/api/auth/oauth2/callback/\(payload.providerId)"
    }
}
