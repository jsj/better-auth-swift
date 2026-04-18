import Foundation

public protocol BetterAuthModule: Sendable {
    var moduleIdentifier: String { get }
    func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime
    func makeRequestHooks(context: BetterAuthModuleContext) -> [any BetterAuthRequestHook]
    func makeAuthStateListeners(context: BetterAuthModuleContext) -> [any BetterAuthAuthStateListener]
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

public struct BetterAuthModuleContext: BetterAuthClientProtocol, Sendable {
    public let configuration: BetterAuthConfiguration
    public let authLifecycle: any BetterAuthAuthPerforming
    public let requestsPerformer: any BetterAuthRequestPerforming
    public let modules: BetterAuthModuleRegistry

    public init(configuration: BetterAuthConfiguration,
                authLifecycle: any BetterAuthAuthPerforming,
                requestsPerformer: any BetterAuthRequestPerforming,
                modules: BetterAuthModuleRegistry = .init())
    {
        self.configuration = configuration
        self.authLifecycle = authLifecycle
        self.requestsPerformer = requestsPerformer
        self.modules = modules
    }
}

public extension BetterAuthModuleRegistry {
    static func build(configuration: BetterAuthConfiguration,
                      authLifecycle: any BetterAuthAuthPerforming,
                      requestsPerformer: any BetterAuthRequestPerforming,
                      modules: [any BetterAuthModule]) -> BetterAuthModuleRegistry
    {
        var runtimes: [String: BetterAuthAnyModuleRuntime] = [:]
        var featureClients: [String: any BetterAuthFeatureClient] = [:]
        var requestHooks: [any BetterAuthRequestHook] = []
        var authStateListeners: [any BetterAuthAuthStateListener] = []
        for module in modules {
            let context = BetterAuthModuleContext(configuration: configuration,
                                                  authLifecycle: authLifecycle,
                                                  requestsPerformer: requestsPerformer,
                                                  modules: BetterAuthModuleRegistry(runtimes: runtimes,
                                                                                    featureClients: featureClients,
                                                                                    requestHooks: requestHooks,
                                                                                    authStateListeners: authStateListeners))
            let runtime = module.configure(context: context)
            runtimes[module.moduleIdentifier] = BetterAuthAnyModuleRuntime(runtime)
            if let featureClient = runtime as? any BetterAuthFeatureClient {
                featureClients[module.moduleIdentifier] = featureClient
            }
            requestHooks.append(contentsOf: module.makeRequestHooks(context: context))
            authStateListeners.append(contentsOf: module.makeAuthStateListeners(context: context))
        }
        return BetterAuthModuleRegistry(runtimes: runtimes,
                                        featureClients: featureClients,
                                        requestHooks: requestHooks,
                                        authStateListeners: authStateListeners)
    }
}
