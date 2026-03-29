import Foundation

struct AuthNetworkClient: Sendable {
    let baseURL: URL
    let transport: BetterAuthTransport
    let retryPolicy: RetryPolicy
    let requestOrigin: String?

    func post<Body: Encodable & Sendable, Response: Decodable>(
        path: String,
        body: Body,
        accessToken: String?
    ) async throws -> Response {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken, body: body)
        return try await executeWithRetry(request)
    }

    func postRaw<Body: Encodable & Sendable>(
        path: String,
        body: Body,
        accessToken: String?
    ) async throws -> (Data, HTTPURLResponse) {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken, body: body)
        return try await executeRawWithRetry(request)
    }

    func post<Response: Decodable>(
        path: String,
        accessToken: String?
    ) async throws -> Response {
        let request = try buildRequest(path: path, method: "POST", accessToken: accessToken)
        return try await executeWithRetry(request)
    }

    func get<Response: Decodable>(
        path: String,
        accessToken: String?
    ) async throws -> Response {
        let request = try buildRequest(path: path, method: "GET", accessToken: accessToken)
        return try await executeWithRetry(request)
    }

    func get<Response: Decodable>(
        path: String,
        queryItems: [URLQueryItem],
        accessToken: String?
    ) async throws -> Response {
        guard let base = URL(string: path, relativeTo: baseURL),
              var components = URLComponents(url: base, resolvingAgainstBaseURL: true) else {
            throw BetterAuthError.invalidURL
        }
        let items = queryItems.filter { $0.value != nil }
        if !items.isEmpty { components.queryItems = items }
        guard let url = components.url else { throw BetterAuthError.invalidURL }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        applyDefaultHeaders(to: &request, accessToken: accessToken)
        return try await executeWithRetry(request)
    }

    // MARK: - Private

    private func buildRequest(
        path: String,
        method: String,
        accessToken: String?
    ) throws -> URLRequest {
        guard let url = URL(string: path, relativeTo: baseURL) else {
            throw BetterAuthError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        applyDefaultHeaders(to: &request, accessToken: accessToken)
        return request
    }

    private func buildRequest<Body: Encodable>(
        path: String,
        method: String,
        accessToken: String?,
        body: Body
    ) throws -> URLRequest {
        var request = try buildRequest(path: path, method: method, accessToken: accessToken)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        return request
    }

    private func applyDefaultHeaders(to request: inout URLRequest, accessToken: String?) {
        if let accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        } else if let requestOrigin, request.value(forHTTPHeaderField: "Origin") == nil {
            request.setValue(requestOrigin, forHTTPHeaderField: "Origin")
        }
    }

    private func executeWithRetry<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        var lastError: Error?
        for attempt in 0...retryPolicy.maxRetries {
            if attempt > 0 {
                let delay = retryPolicy.delay(for: attempt)
                try await Task.sleep(for: .seconds(delay))
            }
            do {
                let (data, response) = try await transport.execute(request)
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw BetterAuthError.invalidResponse
                }
                guard (200..<300).contains(httpResponse.statusCode) else {
                    let error = ErrorParsing.parse(statusCode: httpResponse.statusCode, data: data)
                    if retryPolicy.isRetryable(statusCode: httpResponse.statusCode), attempt < retryPolicy.maxRetries {
                        lastError = error
                        continue
                    }
                    throw error
                }
                return try BetterAuthCoding.makeDecoder().decode(Response.self, from: data)
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

    private func executeRawWithRetry(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var lastError: Error?
        for attempt in 0...retryPolicy.maxRetries {
            if attempt > 0 {
                let delay = retryPolicy.delay(for: attempt)
                try await Task.sleep(for: .seconds(delay))
            }
            do {
                let (data, response) = try await transport.execute(request)
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw BetterAuthError.invalidResponse
                }
                guard (200..<300).contains(httpResponse.statusCode) else {
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
