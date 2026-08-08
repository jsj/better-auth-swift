import Foundation

struct AuthNetworkClient {
    private let pipeline: BetterAuthHTTPPipeline

    init(baseURL: URL,
         transport: BetterAuthTransport,
         retryPolicy: RetryPolicy,
         requestOrigin: String?,
         timeoutInterval: TimeInterval)
    {
        pipeline = BetterAuthHTTPPipeline(requestBuilder: BetterAuthHTTPRequestBuilder(baseURL: baseURL,
                                                                                       requestOrigin: requestOrigin,
                                                                                       timeoutInterval: timeoutInterval),
                                          transport: transport,
                                          retryPolicy: retryPolicy)
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
        let request = try pipeline.makeRequest(path: path,
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
        try pipeline.makeRequest(path: path, method: method, accessToken: accessToken)
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
        try await pipeline.executeDecoding(request, decoder: BetterAuthCoding.makeDecoder())
    }

    private func execute(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try await pipeline.execute(request, statusValidation: .validateSuccess)
    }
}

extension AuthNetworkClient: BetterAuthTransporting {}

enum BetterAuthHTTPStatusValidation: Equatable {
    case validateSuccess
    case preserve
}

struct BetterAuthHTTPPipeline {
    let requestBuilder: BetterAuthHTTPRequestBuilder
    let transport: BetterAuthTransport
    let retryPolicy: RetryPolicy

    init(configuration: BetterAuthConfiguration,
         transport: BetterAuthTransport)
    {
        self.init(requestBuilder: BetterAuthHTTPRequestBuilder(configuration: configuration),
                  transport: transport,
                  retryPolicy: configuration.retryPolicy)
    }

    init(requestBuilder: BetterAuthHTTPRequestBuilder,
         transport: BetterAuthTransport,
         retryPolicy: RetryPolicy)
    {
        self.requestBuilder = requestBuilder
        self.transport = transport
        self.retryPolicy = retryPolicy
    }

    func makeRequest(path: String,
                     method: String,
                     headers: [String: String] = [:],
                     body: Data? = nil,
                     accessToken: String? = nil,
                     queryItems: [URLQueryItem] = []) throws -> URLRequest
    {
        try requestBuilder.makeRequest(path: path,
                                       method: method,
                                       headers: headers,
                                       body: body,
                                       accessToken: accessToken,
                                       queryItems: queryItems)
    }

    func executeDecoding<Response: Decodable>(_ request: URLRequest,
                                              decoder: JSONDecoder = BetterAuthCoding
                                                  .makeDecoder()) async throws -> Response
    {
        let (data, response) = try await execute(request, statusValidation: .validateSuccess)
        return try BetterAuthHTTPResponse.decode(Response.self,
                                                 data: data,
                                                 response: response,
                                                 decoder: decoder)
    }

    func execute(_ request: URLRequest,
                 statusValidation: BetterAuthHTTPStatusValidation = .validateSuccess,
                 allowsTransientRetry: Bool = true) async throws
        -> (Data, HTTPURLResponse)
    {
        let retryLimit = allowsTransientRetry ? retryPolicy.maxRetries : 0
        var lastError: Error?
        for attempt in 0 ... retryLimit {
            if attempt > 0 {
                let delay = retryPolicy.delay(for: attempt)
                try await Task.sleep(for: .seconds(delay))
            }
            do {
                let (data, response) = try await transport.execute(request)
                guard let httpResponse = response as? HTTPURLResponse else {
                    throw BetterAuthError.invalidResponse
                }
                if retryPolicy.isRetryable(statusCode: httpResponse.statusCode), attempt < retryLimit {
                    lastError = ErrorParsing.parse(statusCode: httpResponse.statusCode, data: data)
                    continue
                }
                if statusValidation == .validateSuccess {
                    try BetterAuthHTTPResponse.validateSuccess(data: data, response: httpResponse)
                }
                return (data, httpResponse)
            } catch let error as BetterAuthError {
                throw error
            } catch {
                if retryPolicy.isRetryable(error: error), attempt < retryLimit {
                    lastError = error
                    continue
                }
                throw error
            }
        }
        throw lastError ?? BetterAuthError.invalidResponse
    }
}

enum BetterAuthHTTPResponse {
    static func validateSuccess(data: Data, response: HTTPURLResponse) throws {
        guard (200 ..< 300).contains(response.statusCode) else {
            throw ErrorParsing.parse(statusCode: response.statusCode, data: data)
        }
    }

    static func decode<Response: Decodable>(_ type: Response.Type,
                                            data: Data,
                                            response: HTTPURLResponse,
                                            decoder: JSONDecoder) throws -> Response
    {
        try validateSuccess(data: data, response: response)
        return try decoder.decode(type, from: data)
    }
}
