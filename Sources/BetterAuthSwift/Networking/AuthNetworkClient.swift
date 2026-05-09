import Foundation

struct AuthNetworkClient {
    let baseURL: URL
    let transport: BetterAuthTransport
    let retryPolicy: RetryPolicy
    let requestOrigin: String?
    let timeoutInterval: TimeInterval

    private var requestBuilder: BetterAuthHTTPRequestBuilder {
        BetterAuthHTTPRequestBuilder(baseURL: baseURL,
                                     requestOrigin: requestOrigin,
                                     timeoutInterval: timeoutInterval)
    }

    func post<Response: Decodable>(path: String,
                                   body: some Encodable & Sendable,
                                   accessToken: String?) async throws -> Response
    {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken, body: body)
        return try await execute(request)
    }

    func postRaw(path: String,
                 body: some Encodable & Sendable,
                 accessToken: String?) async throws -> (Data, HTTPURLResponse)
    {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken, body: body)
        return try await execute(request)
    }

    func post<Response: Decodable>(path: String,
                                   accessToken: String?) async throws -> Response
    {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken)
        return try await execute(request)
    }

    func get<Response: Decodable>(path: String,
                                  accessToken: String?) async throws -> Response
    {
        let request = try buildRequest(path: path, method: "GET", accessToken: accessToken)
        return try await execute(request)
    }

    func get<Response: Decodable>(path: String,
                                  queryItems: [URLQueryItem],
                                  accessToken: String?) async throws -> Response
    {
        let request = try requestBuilder.makeRequest(path: path,
                                                     method: "GET",
                                                     accessToken: accessToken,
                                                     queryItems: queryItems)
        return try await execute(request)
    }

    // MARK: - Private

    private func buildRequest(path: String,
                              method: String,
                              accessToken: String?) throws -> URLRequest
    {
        try requestBuilder.makeRequest(path: path, method: method, accessToken: accessToken)
    }

    private func buildRequest(path: String,
                              method: String,
                              accessToken: String?,
                              body: some Encodable) throws -> URLRequest
    {
        var request = try buildRequest(path: path, method: method, accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try BetterAuthCoding.makeEncoder().encode(body)
        return request
    }

    private func execute<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        let (data, _) = try await execute(request)
        return try BetterAuthCoding.makeDecoder().decode(Response.self, from: data)
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var lastError: Error?
        for attempt in 0 ... retryPolicy.maxRetries {
            if attempt > 0 {
                let delay = retryPolicy.delay(for: attempt)
                try await Task.sleep(for: .seconds(delay))
            }
            do {
                let (data, response) = try await transport.execute(request)
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw BetterAuthError.invalidResponse
                }
                guard (200 ..< 300).contains(httpResponse.statusCode) else {
                    let error = ErrorParsing.parse(statusCode: httpResponse.statusCode, data: data)
                    if retryPolicy.isRetryable(statusCode: httpResponse.statusCode), attempt < retryPolicy.maxRetries {
                        lastError = error
                        continue
                    }
                    throw error
                }
                return (data, httpResponse)
            } catch let error as BetterAuthError {
                throw error
            } catch {
                if retryPolicy.isRetryable(error: error), attempt < retryPolicy.maxRetries {
                    lastError = error
                    continue
                }
                throw error
            }
        }
        throw lastError ?? BetterAuthError.invalidResponse
    }
}

extension AuthNetworkClient: BetterAuthTransporting {}
