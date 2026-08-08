import Foundation

public protocol BetterAuthModule: Sendable {
    var moduleIdentifier: String { get }
    func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime
    func makeRequestHooks(context: BetterAuthModuleContext) -> [any BetterAuthRequestHook]
    func makeAuthStateListeners(context: BetterAuthModuleContext) -> [any BetterAuthAuthStateListener]
}

public extension BetterAuthModule {
    func makeRequestHooks(context _: BetterAuthModuleContext) -> [any BetterAuthRequestHook] {
        []
    }

    func makeAuthStateListeners(context _: BetterAuthModuleContext) -> [any BetterAuthAuthStateListener] {
        []
    }
}

public protocol BetterAuthModuleRuntime: Sendable {
    var moduleIdentifier: String { get }
}

public protocol BetterAuthFeatureClient: Sendable {}

public protocol BetterAuthRequestHook: Sendable {
    func prepare(_ request: URLRequest) async throws -> URLRequest
}

public protocol BetterAuthAuthStateListener: Sendable {
    func authStateDidChange(_ change: AuthStateChange) async
}

public struct BetterAuthAuthFeatures: Sendable {
    public let sessionLifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching
    public let sessionOutcomes: any BetterAuthSessionOutcomeApplying
    public let authOperationThrottle: any BetterAuthAuthOperationThrottling
    public let oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming
    public let twoFactorAuth: any BetterAuthTwoFactorPerforming
    public let passkeyAuth: any BetterAuthPasskeyPerforming
    public let accountAuth: any BetterAuthAccountPerforming
    public let sessionAdministration: any BetterAuthSessionAdministrating

    public init(sessionLifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching,
                sessionOutcomes: any BetterAuthSessionOutcomeApplying,
                authOperationThrottle: any BetterAuthAuthOperationThrottling,
                oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming,
                twoFactorAuth: any BetterAuthTwoFactorPerforming,
                passkeyAuth: any BetterAuthPasskeyPerforming,
                accountAuth: any BetterAuthAccountPerforming,
                sessionAdministration: any BetterAuthSessionAdministrating)
    {
        self.sessionLifecycle = sessionLifecycle
        self.sessionOutcomes = sessionOutcomes
        self.authOperationThrottle = authOperationThrottle
        self.oneTimeCodeAuth = oneTimeCodeAuth
        self.twoFactorAuth = twoFactorAuth
        self.passkeyAuth = passkeyAuth
        self.accountAuth = accountAuth
        self.sessionAdministration = sessionAdministration
    }
}

public struct BetterAuthAnyModuleRuntime: BetterAuthModuleRuntime {
    public let moduleIdentifier: String
    private let storage: any BetterAuthModuleRuntime

    private struct IdentifierOnlyRuntime: BetterAuthModuleRuntime {
        let moduleIdentifier: String
    }

    public init(_ runtime: some BetterAuthModuleRuntime) {
        moduleIdentifier = runtime.moduleIdentifier
        storage = runtime
    }

    public init(moduleIdentifier: String) {
        self.moduleIdentifier = moduleIdentifier
        storage = IdentifierOnlyRuntime(moduleIdentifier: moduleIdentifier)
    }

    public func unwrap<Runtime>(as type: Runtime.Type = Runtime.self) -> Runtime? {
        storage as? Runtime
    }
}

public struct BetterAuthModuleRegistry: Sendable {
    private let runtimes: [String: BetterAuthAnyModuleRuntime]
    private let featureClients: [String: any BetterAuthFeatureClient]
    private let requestHooks: [any BetterAuthRequestHook]
    private let authStateListeners: [any BetterAuthAuthStateListener]

    public init(runtimes: [String: BetterAuthAnyModuleRuntime] = [:],
                featureClients: [String: any BetterAuthFeatureClient] = [:],
                requestHooks: [any BetterAuthRequestHook] = [],
                authStateListeners: [any BetterAuthAuthStateListener] = [])
    {
        self.runtimes = runtimes
        self.featureClients = featureClients
        self.requestHooks = requestHooks
        self.authStateListeners = authStateListeners
    }

    public func runtime(for identifier: String) -> BetterAuthAnyModuleRuntime? {
        runtimes[identifier]
    }

    public func runtime<Runtime>(for identifier: String, as type: Runtime.Type = Runtime.self) -> Runtime? {
        runtimes[identifier]?.unwrap(as: type)
    }

    public var registeredModuleIdentifiers: [String] {
        runtimes.keys.sorted()
    }

    public func featureClient<Client>(for identifier: String, as type: Client.Type = Client.self) -> Client? {
        featureClients[identifier] as? Client
    }

    public var registeredFeatureClientIdentifiers: [String] {
        featureClients.keys.sorted()
    }

    public var isEmpty: Bool {
        runtimes.isEmpty && featureClients.isEmpty && requestHooks.isEmpty && authStateListeners.isEmpty
    }

    public var registeredRequestHooks: [any BetterAuthRequestHook] {
        requestHooks
    }

    public var registeredAuthStateListeners: [any BetterAuthAuthStateListener] {
        authStateListeners
    }
}

public struct BetterAuthDuplicateModuleIdentifierError: Error, Sendable, Equatable, CustomStringConvertible {
    public let identifier: String

    public init(identifier: String) {
        self.identifier = identifier
    }

    public var description: String {
        "Better Auth module identifier '\(identifier)' is registered more than once."
    }
}

public struct BetterAuthModuleNotRegisteredError: LocalizedError, Sendable, Equatable {
    public let identifier: String

    public init(identifier: String) {
        self.identifier = identifier
    }

    public var errorDescription: String? {
        "Register the Better Auth module '\(identifier)' when you create BetterAuthClient."
    }
}

public struct BetterAuthModuleContext: BetterAuthClientProtocol, Sendable {
    public let configuration: BetterAuthConfiguration
    public let authSessionLifecycle: any BetterAuthSessionLifecycle & BetterAuthSessionFetching
    public let sessionOutcomes: any BetterAuthSessionOutcomeApplying
    public let authOperationThrottle: any BetterAuthAuthOperationThrottling
    public let oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming
    public let twoFactorAuth: any BetterAuthTwoFactorPerforming
    public let passkeyAuth: any BetterAuthPasskeyPerforming
    public let accountAuth: any BetterAuthAccountPerforming
    public let sessionAdministration: any BetterAuthSessionAdministrating
    public let requestsPerformer: any BetterAuthRequestPerforming
    public let modules: BetterAuthModuleRegistry

    public init(configuration: BetterAuthConfiguration,
                authFeatures: BetterAuthAuthFeatures,
                requestsPerformer: any BetterAuthRequestPerforming,
                modules: BetterAuthModuleRegistry = .init())
    {
        self.configuration = configuration
        self.authSessionLifecycle = authFeatures.sessionLifecycle
        self.sessionOutcomes = authFeatures.sessionOutcomes
        self.authOperationThrottle = authFeatures.authOperationThrottle
        self.oneTimeCodeAuth = authFeatures.oneTimeCodeAuth
        self.twoFactorAuth = authFeatures.twoFactorAuth
        self.passkeyAuth = authFeatures.passkeyAuth
        self.accountAuth = authFeatures.accountAuth
        self.sessionAdministration = authFeatures.sessionAdministration
        self.requestsPerformer = requestsPerformer
        self.modules = modules
    }
}

public extension BetterAuthModuleRegistry {
    static func validate(_ modules: [any BetterAuthModule]) throws {
        var identifiers: Set<String> = []
        for module in modules where !identifiers.insert(module.moduleIdentifier).inserted {
            throw BetterAuthDuplicateModuleIdentifierError(identifier: module.moduleIdentifier)
        }
    }

    static func build(configuration: BetterAuthConfiguration,
                      authFeatures: BetterAuthAuthFeatures,
                      requestsPerformer: any BetterAuthRequestPerforming,
                      requestPerformerFactory: ([any BetterAuthRequestHook]) -> any BetterAuthRequestPerforming,
                      modules: [any BetterAuthModule]) -> BetterAuthModuleRegistry
    {
        var runtimes: [String: BetterAuthAnyModuleRuntime] = [:]
        var featureClients: [String: any BetterAuthFeatureClient] = [:]
        var requestHooks: [any BetterAuthRequestHook] = []
        var authStateListeners: [any BetterAuthAuthStateListener] = []
        for module in modules {
            let context = BetterAuthModuleContext(configuration: configuration,
                                                  authFeatures: authFeatures,
                                                  requestsPerformer: requestsPerformer,
                                                  modules: BetterAuthModuleRegistry(runtimes: [:],
                                                                                    featureClients: [:],
                                                                                    requestHooks: requestHooks,
                                                                                    authStateListeners: authStateListeners))
            requestHooks.append(contentsOf: module.makeRequestHooks(context: context))
            authStateListeners.append(contentsOf: module.makeAuthStateListeners(context: context))
        }

        let hookedRequestsPerformer = requestHooks.isEmpty ? requestsPerformer : requestPerformerFactory(requestHooks)
        runtimes.removeAll(keepingCapacity: true)
        featureClients.removeAll(keepingCapacity: true)
        for module in modules {
            let context = BetterAuthModuleContext(configuration: configuration,
                                                  authFeatures: authFeatures,
                                                  requestsPerformer: hookedRequestsPerformer,
                                                  modules: BetterAuthModuleRegistry(runtimes: runtimes,
                                                                                    featureClients: featureClients,
                                                                                    requestHooks: requestHooks,
                                                                                    authStateListeners: authStateListeners))
            let runtime = module.configure(context: context)
            runtimes[module.moduleIdentifier] = BetterAuthAnyModuleRuntime(runtime)
            if let featureClient = runtime as? any BetterAuthFeatureClient {
                featureClients[module.moduleIdentifier] = featureClient
            }
        }
        return BetterAuthModuleRegistry(runtimes: runtimes,
                                        featureClients: featureClients,
                                        requestHooks: requestHooks,
                                        authStateListeners: authStateListeners)
    }

    static func build(configuration: BetterAuthConfiguration,
                      authFeatures: BetterAuthAuthFeatures,
                      requestsPerformer: any BetterAuthRequestPerforming,
                      modules: [any BetterAuthModule]) -> BetterAuthModuleRegistry
    {
        build(configuration: configuration,
              authFeatures: authFeatures,
              requestsPerformer: requestsPerformer,
              requestPerformerFactory: { _ in requestsPerformer },
              modules: modules)
    }
}
