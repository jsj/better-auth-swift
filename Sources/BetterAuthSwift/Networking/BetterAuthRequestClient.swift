import Foundation

/// This HTTP client sends authenticated and unauthenticated requests to your backend.
///
/// Access this client through ``BetterAuthClient/requests``. It attaches bearer tokens automatically.
/// After a `401` response, it refreshes the session and retries once.
public struct BetterAuthRequestClient: BetterAuthRequestPerforming, Sendable {
    private let sessionManager: BetterAuthSessionManager
    private let pipeline: BetterAuthHTTPPipeline
    private let requestHooks: [any BetterAuthRequestHook]
    private let requestBuilder: BetterAuthHTTPRequestBuilder
    private let retryPolicy: RetryPolicy

    init(configuration: BetterAuthConfiguration,
         sessionManager: BetterAuthSessionManager,
         transport: BetterAuthTransport,
         requestHooks: [any BetterAuthRequestHook] = [])
    {
        self.sessionManager = sessionManager
        self.pipeline = BetterAuthHTTPPipeline(transport: transport)
        self.requestHooks = requestHooks
        self.requestBuilder = BetterAuthHTTPRequestBuilder(configuration: configuration)
        self.retryPolicy = configuration.retryPolicy
    }

    /// Sends a raw HTTP request. Returns `(Data, HTTPURLResponse)`.
    ///
    /// The raw client preserves non-2xx responses for callers that need direct HTTP inspection.
    /// After a refresh retry, this method reports a non-2xx response as a `BetterAuthError`.
    public func send(_ request: BetterAuthDataRequest) async throws -> (Data, HTTPURLResponse) {
        try await send(path: request.path,
                       method: request.method,
                       headers: request.headers,
                       body: request.body,
                       requiresAuthentication: request.requiresAuthentication,
                       retryOnUnauthorized: request.retryOnUnauthorized)
    }

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
            try pipeline.validateSuccess(data: retried.0, response: retried.1)
            return retried
        }

        return (data, response)
    }

    /// Sends a request and decodes the JSON response into the inferred `Response` type.
    public func sendJSON<Response: Decodable>(_ request: BetterAuthDataRequest,
                                              decoder: JSONDecoder = BetterAuthCoding
                                                  .makeDecoder()) async throws -> Response
    {
        try await sendJSON(path: request.path,
                           method: request.method,
                           headers: request.headers,
                           body: request.body,
                           requiresAuthentication: request.requiresAuthentication,
                           retryOnUnauthorized: request.retryOnUnauthorized,
                           decoder: decoder)
    }

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

        try pipeline.validateSuccess(data: data, response: response)
        return try decoder.decode(Response.self, from: data)
    }

    /// Sends an `Encodable` body and decodes the JSON response.
    public func sendJSON<Response: Decodable>(path: String,
                                              method: String = "POST",
                                              headers: [String: String] = [:],
                                              body: some Encodable,
                                              requiresAuthentication: Bool = true,
                                              retryOnUnauthorized: Bool = true,
                                              encoder: JSONEncoder = BetterAuthCoding.makeEncoder(),
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

    /// Sends a request with an optional body. Validates the status code and discards the response body.
    public func sendWithoutDecoding(path: String,
                                    method: String = "POST",
                                    headers: [String: String] = [:],
                                    body: (some Encodable)? = nil,
                                    requiresAuthentication: Bool = true,
                                    retryOnUnauthorized: Bool = true,
                                    encoder: JSONEncoder = BetterAuthCoding.makeEncoder()) async throws
    {
        let requestBody = try body.map(encoder.encode)
        let (data, response) = try await send(path: path,
                                              method: method,
                                              headers: headers,
                                              body: requestBody,
                                              requiresAuthentication: requiresAuthentication,
                                              retryOnUnauthorized: retryOnUnauthorized)

        try pipeline.validateSuccess(data: data, response: response)
    }

    private func makeRequest(path: String,
                             method: String,
                             headers: [String: String],
                             body: Data?,
                             requiresAuthentication: Bool) async throws -> URLRequest
    {
        if requiresAuthentication {
            let session = try await sessionManager.validSession()
            return try requestBuilder.makeRequest(path: path,
                                                  method: method,
                                                  headers: headers,
                                                  body: body,
                                                  accessToken: session.session.accessToken)
        }

        return try requestBuilder.makeRequest(path: path, method: method, headers: headers, body: body)
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await pipeline.execute(request, statusValidation: .preserve, retryPolicy: retryPolicy)
    }

    private func preparedRequest(from request: URLRequest) async throws -> URLRequest {
        var prepared = request
        for hook in requestHooks {
            prepared = try await hook.prepare(prepared)
        }
        return prepared
    }
}
