import Foundation

struct BetterAuthCallbackHandler {
    let baseURL: URL
    let endpoints: BetterAuthConfiguration.Endpoints
    let callbackURLSchemes: Set<String>

    func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              acceptsURLScheme(components.scheme)
        else {
            return .unsupported
        }

        let queryItems = components.queryItems ?? []
        if components.path.hasSuffix(endpoints.user.verifyEmailPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .verifyEmail(.init(token: token))
        }
        return .unsupported
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
}
