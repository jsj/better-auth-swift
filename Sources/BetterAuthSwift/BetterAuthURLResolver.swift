import Foundation

enum BetterAuthURLResolver {
    static func resolve(_ path: String, relativeTo baseURL: URL) throws -> URL {
        if let rawURL = URL(string: path), rawURL.scheme != nil || rawURL.host != nil {
            guard sharesOrigin(rawURL, with: baseURL) else {
                throw BetterAuthError.invalidURL
            }
            return rawURL
        }

        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL else {
            throw BetterAuthError.invalidURL
        }

        return url
    }

    private static func sharesOrigin(_ lhs: URL, with rhs: URL) -> Bool {
        lhs.scheme?.lowercased() == rhs.scheme?.lowercased() &&
            lhs.host?.lowercased() == rhs.host?.lowercased() &&
            normalizedPort(for: lhs) == normalizedPort(for: rhs)
    }

    private static func normalizedPort(for url: URL) -> Int? {
        if let port = url.port {
            return port
        }

        switch url.scheme?.lowercased() {
        case "http":
            return 80

        case "https":
            return 443

        default:
            return nil
        }
    }
}
