import Foundation

public enum BetterAuthBackendFeature: String, Codable, Hashable, Sendable, CaseIterable {
    case bearer
    case emailPassword = "email-password"
    case username
    case appleNative = "apple-native"
    case socialOAuth = "social-oauth"
    case genericOAuth = "generic-oauth"
    case anonymous
    case magicLink = "magic-link"
    case emailOTP = "email-otp"
    case phoneOTP = "phone-otp"
    case twoFactor = "two-factor"
    case passkey
    case multiSession = "multi-session"
    case jwt
    case organization

    public static let mobileCore: Set<Self> = [.bearer, .emailPassword]
}

public enum BetterAuthDiagnosticStatus: String, Sendable, Equatable {
    case passed
    case warning
    case failed
    case skipped
}

public struct BetterAuthDiagnosticCheck: Sendable, Equatable {
    public let status: BetterAuthDiagnosticStatus
    public let message: String
    public let statusCode: Int?

    public init(status: BetterAuthDiagnosticStatus, message: String, statusCode: Int? = nil) {
        self.status = status
        self.message = message
        self.statusCode = statusCode
    }
}

public struct BetterAuthBackendDiagnostics: Codable, Sendable, Equatable {
    public let ok: Bool
    public let name: String?
    public let platform: String?
    public let authBasePath: String?
    public let features: Set<BetterAuthBackendFeature>
    public let routes: [String: String]

    public init(ok: Bool = true,
                name: String? = nil,
                platform: String? = nil,
                authBasePath: String? = nil,
                features: Set<BetterAuthBackendFeature> = [],
                routes: [String: String] = [:])
    {
        self.ok = ok
        self.name = name
        self.platform = platform
        self.authBasePath = authBasePath
        self.features = features
        self.routes = routes
    }
}

public struct BetterAuthDiagnosticReport: Sendable, Equatable {
    public let baseURL: URL
    public let health: BetterAuthDiagnosticCheck
    public let backendMetadata: BetterAuthDiagnosticCheck
    public let advertisedFeatures: Set<BetterAuthBackendFeature>
    public let missingFeatures: Set<BetterAuthBackendFeature>
    public let metadata: BetterAuthBackendDiagnostics?

    public var isCompatible: Bool {
        health.status == .passed && missingFeatures.isEmpty
    }

    public init(baseURL: URL,
                health: BetterAuthDiagnosticCheck,
                backendMetadata: BetterAuthDiagnosticCheck,
                advertisedFeatures: Set<BetterAuthBackendFeature>,
                missingFeatures: Set<BetterAuthBackendFeature>,
                metadata: BetterAuthBackendDiagnostics?)
    {
        self.baseURL = baseURL
        self.health = health
        self.backendMetadata = backendMetadata
        self.advertisedFeatures = advertisedFeatures
        self.missingFeatures = missingFeatures
        self.metadata = metadata
    }
}

public struct BetterAuthDiagnosticsClient: Sendable {
    private let configuration: BetterAuthConfiguration
    private let requests: any BetterAuthRequestPerforming

    init(configuration: BetterAuthConfiguration,
         requests: any BetterAuthRequestPerforming)
    {
        self.configuration = configuration
        self.requests = requests
    }

    public func check(expectedFeatures: Set<BetterAuthBackendFeature> = BetterAuthBackendFeature.mobileCore,
                      healthPath: String = "/health",
                      metadataPath: String = "/api/better-auth-swift/diagnostics") async -> BetterAuthDiagnosticReport
    {
        let health = await checkHealth(path: healthPath)
        let metadataResult = await fetchMetadata(path: metadataPath)
        let advertisedFeatures = metadataResult.metadata?.features ?? []
        let missingFeatures = metadataResult.metadata == nil ? [] : expectedFeatures.subtracting(advertisedFeatures)

        return BetterAuthDiagnosticReport(baseURL: configuration.baseURL,
                                          health: health,
                                          backendMetadata: metadataResult.check,
                                          advertisedFeatures: advertisedFeatures,
                                          missingFeatures: missingFeatures,
                                          metadata: metadataResult.metadata)
    }

    private func checkHealth(path: String) async -> BetterAuthDiagnosticCheck {
        do {
            let response: BetterAuthHealthResponse = try await requests.sendJSON(path: path,
                                                                                 requiresAuthentication: false,
                                                                                 retryOnUnauthorized: false)
            guard response.ok else {
                return .init(status: .failed, message: "Health endpoint responded but did not report ok.")
            }
            return .init(status: .passed, message: "Health endpoint is reachable.")
        } catch {
            return diagnosticCheck(for: error, fallbackMessage: "Health endpoint is not reachable.")
        }
    }

    private func fetchMetadata(path: String) async
        -> (check: BetterAuthDiagnosticCheck, metadata: BetterAuthBackendDiagnostics?)
    {
        do {
            let metadata: BetterAuthBackendDiagnostics = try await requests.sendJSON(path: path,
                                                                                     requiresAuthentication: false,
                                                                                     retryOnUnauthorized: false)
            guard metadata.ok else {
                return (.init(status: .failed, message: "Diagnostics endpoint responded but did not report ok."),
                        metadata)
            }
            return (.init(status: .passed, message: "Diagnostics endpoint is reachable."), metadata)
        } catch let error as BetterAuthError where error.statusCode == 404 {
            return (.init(status: .warning,
                          message: "Diagnostics endpoint was not found. Add it to your backend for plugin checks.",
                          statusCode: error.statusCode),
                    nil)
        } catch {
            return (diagnosticCheck(for: error,
                                    fallbackMessage: "Diagnostics endpoint is not reachable."),
                    nil)
        }
    }

    private func diagnosticCheck(for error: Error, fallbackMessage: String) -> BetterAuthDiagnosticCheck {
        if let betterAuthError = error as? BetterAuthError {
            return .init(status: .failed,
                         message: betterAuthError.localizedDescription,
                         statusCode: betterAuthError.statusCode)
        }
        return .init(status: .failed, message: fallbackMessage)
    }
}

private struct BetterAuthHealthResponse: Decodable {
    let ok: Bool
}

public extension BetterAuthClient {
    var diagnostics: BetterAuthDiagnosticsClient {
        BetterAuthDiagnosticsClient(configuration: configuration, requests: requests)
    }
}
