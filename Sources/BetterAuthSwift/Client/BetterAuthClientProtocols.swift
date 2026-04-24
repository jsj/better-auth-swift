import Foundation

public struct BetterAuthDataRequest: Sendable {
    public var path: String
    public var method: String
    public var headers: [String: String]
    public var body: Data?
    public var requiresAuthentication: Bool
    public var retryOnUnauthorized: Bool

    public init(path: String,
                method: String = "GET",
                headers: [String: String] = [:],
                body: Data? = nil,
                requiresAuthentication: Bool = true,
                retryOnUnauthorized: Bool = true)
    {
        self.path = path
        self.method = method
        self.headers = headers
        self.body = body
        self.requiresAuthentication = requiresAuthentication
        self.retryOnUnauthorized = retryOnUnauthorized
    }
}

public protocol BetterAuthRequestPerforming: Sendable {
    func send(_ request: BetterAuthDataRequest) async throws -> (Data, HTTPURLResponse)

    func sendJSON<Response: Decodable>(_ request: BetterAuthDataRequest,
                                       decoder: JSONDecoder) async throws -> Response
}

public extension BetterAuthRequestPerforming {
    func send(path: String,
              method: String = "GET",
              headers: [String: String] = [:],
              body: Data? = nil,
              requiresAuthentication: Bool = true,
              retryOnUnauthorized: Bool = true) async throws -> (Data, HTTPURLResponse)
    {
        try await send(.init(path: path,
                             method: method,
                             headers: headers,
                             body: body,
                             requiresAuthentication: requiresAuthentication,
                             retryOnUnauthorized: retryOnUnauthorized))
    }

    func sendJSON<Response: Decodable>(path: String,
                                       method: String = "GET",
                                       headers: [String: String] = [:],
                                       body: Data? = nil,
                                       requiresAuthentication: Bool = true,
                                       retryOnUnauthorized: Bool = true,
                                       decoder: JSONDecoder = BetterAuthCoding.makeDecoder()) async throws -> Response
    {
        let (data, response) = try await send(.init(path: path,
                                                    method: method,
                                                    headers: headers,
                                                    body: body,
                                                    requiresAuthentication: requiresAuthentication,
                                                    retryOnUnauthorized: retryOnUnauthorized))
        guard (200 ..< 300).contains(response.statusCode) else {
            throw ErrorParsing.parse(statusCode: response.statusCode, data: data)
        }
        return try decoder.decode(Response.self, from: data)
    }

    func sendJSON<Response: Decodable>(path: String,
                                       method: String = "POST",
                                       headers: [String: String] = [:],
                                       body: some Encodable,
                                       requiresAuthentication: Bool = true,
                                       retryOnUnauthorized: Bool = true,
                                       encoder: JSONEncoder = BetterAuthCoding.makeEncoder(),
                                       decoder: JSONDecoder = BetterAuthCoding.makeDecoder()) async throws -> Response
    {
        var mergedHeaders = headers
        mergedHeaders["Content-Type"] = mergedHeaders["Content-Type"] ?? "application/json"

        return try await sendJSON(.init(path: path,
                                        method: method,
                                        headers: mergedHeaders,
                                        body: encoder.encode(body),
                                        requiresAuthentication: requiresAuthentication,
                                        retryOnUnauthorized: retryOnUnauthorized),
                                  decoder: decoder)
    }
}

public protocol BetterAuthClientProtocol: Sendable {
    var configuration: BetterAuthConfiguration { get }
    var authLifecycle: any BetterAuthAuthPerforming { get }
    var requestsPerformer: any BetterAuthRequestPerforming { get }
    var modules: BetterAuthModuleRegistry { get }
}

public protocol BetterAuthModuleSupporting: BetterAuthClientProtocol {
    func moduleRuntime<Runtime>(for identifier: String, as type: Runtime.Type) -> Runtime?
    func featureClient<Client>(for identifier: String, as type: Client.Type) -> Client?
}

public extension BetterAuthModuleSupporting {
    func moduleRuntime<Runtime>(for identifier: String, as type: Runtime.Type = Runtime.self) -> Runtime? {
        modules.runtime(for: identifier, as: type)
    }

    func featureClient<Client>(for identifier: String, as type: Client.Type = Client.self) -> Client? {
        modules.featureClient(for: identifier, as: type)
    }
}
