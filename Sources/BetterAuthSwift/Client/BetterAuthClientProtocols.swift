import Foundation

public struct BetterAuthDataRequest: Sendable {
    public var path: String
    public var method: String
    public var headers: [String: String]
    public var body: Data?
    public var requiresAuthentication: Bool
    public var retryOnUnauthorized: Bool
    /// `nil` retries GET/HEAD/OPTIONS only. Set explicitly for application-specific semantics.
    public var allowsTransientRetry: Bool?

    public init(path: String,
                method: String = "GET",
                headers: [String: String] = [:],
                body: Data? = nil,
                requiresAuthentication: Bool = true,
                retryOnUnauthorized: Bool = true,
                allowsTransientRetry: Bool? = nil)
    {
        self.path = path
        self.method = method
        self.headers = headers
        self.body = body
        self.requiresAuthentication = requiresAuthentication
        self.retryOnUnauthorized = retryOnUnauthorized
        self.allowsTransientRetry = allowsTransientRetry
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
              retryOnUnauthorized: Bool = true,
              allowsTransientRetry: Bool? = nil) async throws -> (Data, HTTPURLResponse)
    {
        try await send(.init(path: path,
                             method: method,
                             headers: headers,
                             body: body,
                             requiresAuthentication: requiresAuthentication,
                             retryOnUnauthorized: retryOnUnauthorized,
                             allowsTransientRetry: allowsTransientRetry))
    }

    func sendJSON<Response: Decodable>(path: String,
                                       method: String = "GET",
                                       headers: [String: String] = [:],
                                       body: Data? = nil,
                                       requiresAuthentication: Bool = true,
                                       retryOnUnauthorized: Bool = true,
                                       allowsTransientRetry: Bool? = nil,
                                       decoder: JSONDecoder = BetterAuthCoding.makeDecoder()) async throws -> Response
    {
        let (data, response) = try await send(.init(path: path,
                                                    method: method,
                                                    headers: headers,
                                                    body: body,
                                                    requiresAuthentication: requiresAuthentication,
                                                    retryOnUnauthorized: retryOnUnauthorized,
                                                    allowsTransientRetry: allowsTransientRetry))
        return try BetterAuthHTTPResponse.decode(Response.self,
                                                 data: data,
                                                 response: response,
                                                 decoder: decoder)
    }

    func sendJSON<Response: Decodable>(path: String,
                                       method: String = "POST",
                                       headers: [String: String] = [:],
                                       body: some Encodable,
                                       requiresAuthentication: Bool = true,
                                       retryOnUnauthorized: Bool = true,
                                       allowsTransientRetry: Bool? = nil,
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
                                        retryOnUnauthorized: retryOnUnauthorized,
                                        allowsTransientRetry: allowsTransientRetry),
                                  decoder: decoder)
    }
}

public protocol BetterAuthClientProtocol: Sendable {
    var configuration: BetterAuthConfiguration { get }
    var authSessionLifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching { get }
    var oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming { get }
    var twoFactorAuth: any BetterAuthTwoFactorPerforming { get }
    var passkeyAuth: any BetterAuthPasskeyPerforming { get }
    var accountAuth: any BetterAuthAccountPerforming { get }
    var sessionAdministration: any BetterAuthSessionAdministrating { get }
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
