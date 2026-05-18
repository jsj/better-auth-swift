import Foundation

struct AuthNetworkClient {
    let baseURL: URL
    let transport: BetterAuthTransport
    let retryPolicy: RetryPolicy
    let requestOrigin: String?
    let timeoutInterval: TimeInterval

    private var pipeline: BetterAuthHTTPPipeline {
        BetterAuthHTTPPipeline(transport: transport)
    }

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
        try await pipeline.executeDecoding(request,
                                           decoder: BetterAuthCoding.makeDecoder(),
                                           retryPolicy: retryPolicy)
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await pipeline.execute(request,
                                   statusValidation: .validateSuccess,
                                   retryPolicy: retryPolicy)
    }
}

extension AuthNetworkClient: BetterAuthTransporting {}

enum BetterAuthHTTPStatusValidation: Equatable {
    case validateSuccess
    case preserve
}

struct BetterAuthHTTPPipeline {
    let transport: BetterAuthTransport

    func executeDecoding<Response: Decodable>(_ request: URLRequest,
                                              decoder: JSONDecoder = BetterAuthCoding.makeDecoder(),
                                              retryPolicy: RetryPolicy = .none) async throws -> Response
    {
        let (data, _) = try await execute(request,
                                          statusValidation: .validateSuccess,
                                          retryPolicy: retryPolicy)
        return try decoder.decode(Response.self, from: data)
    }

    func execute(_ request: URLRequest,
                 statusValidation: BetterAuthHTTPStatusValidation = .validateSuccess,
                 retryPolicy: RetryPolicy = .none) async throws -> (Data, HTTPURLResponse)
    {
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
                do {
                    if statusValidation == .validateSuccess {
                        try validateSuccess(data: data, response: httpResponse)
                    }
                } catch {
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

    func validateSuccess(data: Data, response: HTTPURLResponse) throws {
        guard (200 ..< 300).contains(response.statusCode) else {
            throw ErrorParsing.parse(statusCode: response.statusCode, data: data)
        }
    }
}
