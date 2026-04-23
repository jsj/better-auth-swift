import Foundation

/// HTTP client for making authenticated (and unauthenticated) requests to your backend.
///
/// Access via ``BetterAuthClient/requests``. Automatically attaches bearer tokens
/// and retries once on `401` after refreshing the session.
public struct BetterAuthRequestClient: BetterAuthRequestPerforming, Sendable {
    private let configuration: BetterAuthConfiguration
    private let sessionManager: BetterAuthSessionManager
    private let transport: BetterAuthTransport
    private let requestHooks: [any BetterAuthRequestHook]

    init(configuration: BetterAuthConfiguration,
         sessionManager: BetterAuthSessionManager,
         transport: BetterAuthTransport,
         requestHooks: [any BetterAuthRequestHook] = [])
    {
        self.configuration = configuration
        self.sessionManager = sessionManager
        self.transport = transport
        self.requestHooks = requestHooks
    }

    /// Sends a raw HTTP request, returning `(Data, HTTPURLResponse)`.
    ///
    /// The raw client preserves non-2xx responses for callers that need direct HTTP inspection.
    /// After a 401-triggered refresh retry, any non-2xx retried response is surfaced as `BetterAuthError`
    /// to avoid silently masking retry failures.
    public func send(path: String,
                     method: String = "GET",
                     headers: [String: String] = [:],
                     body: Data? = nil,
                     requiresAuthentication: Bool = true,
                     retryOnUnauthorized: Bool = true) async throws -> (Data, HTTPURLResponse)
    {
        var request = try await makeRequest(path: path,
                                            method: method,
                                            headers: headers,
                                            body: body,
                                            requiresAuthentication: requiresAuthentication)

        let (data, response) = try await execute(preparedRequest(from: request))
        if response.statusCode == 401, retryOnUnauthorized, requiresAuthentication {
            _ = try await sessionManager.refreshSession()
            request = try await makeRequest(path: path,
                                            method: method,
                                            headers: headers,
                                            body: body,
                                            requiresAuthentication: requiresAuthentication)
            let retried = try await execute(preparedRequest(from: request))
            guard (200 ..< 300).contains(retried.1.statusCode) else {
                throw ErrorParsing.parse(statusCode: retried.1.statusCode, data: retried.0)
            }
            return retried
        }

        return (data, response)
    }

    /// Sends a request and decodes the JSON response into the inferred `Response` type.
    public func sendJSON<Response: Decodable>(path: String,
                                              method: String = "GET",
                                              headers: [String: String] = [:],
                                              body: Data? = nil,
                                              requiresAuthentication: Bool = true,
                                              retryOnUnauthorized: Bool = true,
                                              decoder: JSONDecoder = BetterAuthCoding
                                                  .makeDecoder()) async throws -> Response
    {
        let (data, response) = try await send(path: path,
                                              method: method,
                                              headers: headers,
                                              body: body,
                                              requiresAuthentication: requiresAuthentication,
                                              retryOnUnauthorized: retryOnUnauthorized)

        guard (200 ..< 300).contains(response.statusCode) else {
            throw ErrorParsing.parse(statusCode: response.statusCode, data: data)
        }

        return try decoder.decode(Response.self, from: data)
    }

    /// Sends an `Encodable` body and decodes the JSON response.
    public func sendJSON<Response: Decodable>(path: String,
                                              method: String = "POST",
                                              headers: [String: String] = [:],
                                              body: some Encodable,
                                              requiresAuthentication: Bool = true,
                                              retryOnUnauthorized: Bool = true,
                                              encoder: JSONEncoder = JSONEncoder(),
                                              decoder: JSONDecoder = BetterAuthCoding
                                                  .makeDecoder()) async throws -> Response
    {
        var mergedHeaders = headers
        mergedHeaders["Content-Type"] = mergedHeaders["Content-Type"] ?? "application/json"

        return try await sendJSON(path: path,
                                  method: method,
                                  headers: mergedHeaders,
                                  body: encoder.encode(body),
                                  requiresAuthentication: requiresAuthentication,
                                  retryOnUnauthorized: retryOnUnauthorized,
                                  decoder: decoder)
    }

    /// Sends a request with an optional body, validating the status code but discarding the response body.
    public func sendWithoutDecoding(path: String,
                                    method: String = "POST",
                                    headers: [String: String] = [:],
                                    body: (some Encodable)? = nil,
                                    requiresAuthentication: Bool = true,
                                    retryOnUnauthorized: Bool = true,
                                    encoder: JSONEncoder = JSONEncoder()) async throws
    {
        let requestBody = try body.map(encoder.encode)
        let (data, response) = try await send(path: path,
                                              method: method,
                                              headers: headers,
                                              body: requestBody,
                                              requiresAuthentication: requiresAuthentication,
                                              retryOnUnauthorized: retryOnUnauthorized)

        guard (200 ..< 300).contains(response.statusCode) else {
            throw ErrorParsing.parse(statusCode: response.statusCode, data: data)
        }
    }

    private func makeRequest(path: String,
                             method: String,
                             headers: [String: String],
                             body: Data?,
                             requiresAuthentication: Bool) async throws -> URLRequest
    {
        if requiresAuthentication {
            var request = try await sessionManager.authorizedRequest(path: path, method: method)
            headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
            request.httpBody = body
            return request
        }

        let url = try BetterAuthURLResolver.resolve(path, relativeTo: configuration.baseURL)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = configuration.timeoutInterval
        if let requestOrigin = configuration.requestOrigin, request.value(forHTTPHeaderField: "Origin") == nil {
            request.setValue(requestOrigin, forHTTPHeaderField: "Origin")
        }
        headers.forEach { request.setValue($1, forHTTPHeaderField: $0) }
        request.httpBody = body
        return request
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await transport.execute(request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw BetterAuthError.invalidResponse
        }
        return (data, httpResponse)
    }

    private func preparedRequest(from request: URLRequest) async throws -> URLRequest {
        var prepared = request
        for hook in requestHooks {
            prepared = try await hook.prepare(prepared)
        }
        return prepared
    }
}
