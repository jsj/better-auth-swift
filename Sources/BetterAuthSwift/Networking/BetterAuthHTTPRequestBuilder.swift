import Foundation

struct BetterAuthHTTPRequestBuilder {
    let baseURL: URL
    let requestOrigin: String?
    let timeoutInterval: TimeInterval

    init(configuration: BetterAuthConfiguration) {
        self.baseURL = configuration.baseURL
        self.requestOrigin = configuration.requestOrigin
        self.timeoutInterval = configuration.timeoutInterval
    }

    init(baseURL: URL, requestOrigin: String?, timeoutInterval: TimeInterval) {
        self.baseURL = baseURL
        self.requestOrigin = requestOrigin
        self.timeoutInterval = timeoutInterval
    }

    func makeRequest(path: String,
                     method: String,
                     headers: [String: String] = [:],
                     body: Data? = nil,
                     accessToken: String? = nil,
                     queryItems: [URLQueryItem] = []) throws -> URLRequest
    {
        let url = try resolveURL(path: path, queryItems: queryItems)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = timeoutInterval
        if let accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        if let requestOrigin {
            request.setValue(requestOrigin, forHTTPHeaderField: "Origin")
        }
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        request.httpBody = body
        return request
    }

    private func resolveURL(path: String, queryItems: [URLQueryItem]) throws -> URL {
        let url = try BetterAuthURLResolver.resolve(path, relativeTo: baseURL)
        let items = queryItems.filter { $0.value != nil }
        guard !items.isEmpty else { return url }
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            throw BetterAuthError.invalidURL
        }
        components.queryItems = items
        guard let resolvedURL = components.url else { throw BetterAuthError.invalidURL }
        return resolvedURL
    }
}
