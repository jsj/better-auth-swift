import Foundation

struct BetterAuthCallbackHandler {
    private static let providerPlaceholder = "{providerId}"
    let baseURL: URL
    let endpoints: BetterAuthConfiguration.Endpoints
    let callbackURLSchemes: Set<String>

    func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            return .unsupported
        }
        guard acceptsURLScheme(components.scheme) else {
            return .unsupported
        }

        let path = components.path
        let queryItems = components.queryItems ?? []

        if let code = queryItems.first(where: { $0.name == "code" })?.value,
           let state = queryItems.first(where: { $0.name == "state" })?.value,
           let providerId = providerID(from: path)
        {
            let issuer = queryItems.first(where: { $0.name == "iss" })?.value
            return .genericOAuth(.init(providerId: providerId, code: code, state: state, issuer: issuer))
        }

        if path.hasSuffix(endpoints.magicLink.verifyPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .magicLink(.init(token: token,
                                    callbackURL: queryItems.first(where: { $0.name == "callbackURL" })?.value,
                                    newUserCallbackURL: queryItems.first(where: { $0.name == "newUserCallbackURL" })?
                                        .value,
                                    errorCallbackURL: queryItems.first(where: { $0.name == "errorCallbackURL" })?
                                        .value))
        }

        if path.hasSuffix(endpoints.user.verifyEmailPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .verifyEmail(.init(token: token))
        }

        return .unsupported
    }

    func oauthCallbackPath(for payload: GenericOAuthCallbackRequest) -> String {
        var components = URLComponents()
        components.path = endpoints.oauth.genericOAuthCallbackPath
            .replacingOccurrences(of: Self.providerPlaceholder, with: payload.providerId)
        components.queryItems = [URLQueryItem(name: "code", value: payload.code),
                                 URLQueryItem(name: "state", value: payload.state)]
        if let issuer = payload.issuer {
            components.queryItems?.append(URLQueryItem(name: "iss", value: issuer))
        }
        return components.string ?? components.path
    }

    private func acceptsURLScheme(_ scheme: String?) -> Bool {
        guard let scheme = scheme?.lowercased(), !scheme.isEmpty else {
            return false
        }

        var allowedSchemes = callbackURLSchemes
        if let baseScheme = baseURL.scheme?.lowercased(), !baseScheme.isEmpty {
            allowedSchemes.insert(baseScheme)
        }
        return allowedSchemes.contains(scheme)
    }

    private func providerID(from path: String) -> String? {
        if let configuredProviderID = configuredProviderID(from: path) {
            return configuredProviderID
        }

        return legacyProviderID(from: path)
    }

    private func configuredProviderID(from path: String) -> String? {
        let template = endpoints.oauth.genericOAuthCallbackPath
        guard let placeholderRange = template.range(of: Self.providerPlaceholder) else {
            return nil
        }

        let prefix = String(template[..<placeholderRange.lowerBound])
        let suffix = String(template[placeholderRange.upperBound...])

        guard path.hasPrefix(prefix), path.hasSuffix(suffix) else {
            return nil
        }

        let startIndex = path.index(path.startIndex, offsetBy: prefix.count)
        let endIndex = path.index(path.endIndex, offsetBy: -suffix.count)
        guard startIndex <= endIndex else {
            return nil
        }

        let providerID = String(path[startIndex ..< endIndex])
        guard !providerID.isEmpty else {
            return nil
        }

        return providerID.removingPercentEncoding ?? providerID
    }

    private func legacyProviderID(from path: String) -> String? {
        let pathComponents = path.split(separator: "/")
        guard let callbackIndex = pathComponents.firstIndex(of: "callback"),
              callbackIndex + 1 < pathComponents.count
        else {
            return nil
        }

        let providerID = String(pathComponents[callbackIndex + 1])
        guard !providerID.isEmpty else {
            return nil
        }

        return providerID.removingPercentEncoding ?? providerID
    }
}
