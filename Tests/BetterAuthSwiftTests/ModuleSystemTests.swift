import BetterAuth
import BetterAuthTestHelpers
import Foundation
import Testing

@Suite("Module system")
struct ModuleSystemTests {
    @Test
    func emptyModuleRegistryReportsNoModules() {
        let registry = BetterAuthModuleRegistry()

        #expect(registry.isEmpty == true)
        #expect(registry.registeredModuleIdentifiers.isEmpty)
        #expect(registry.registeredFeatureClientIdentifiers.isEmpty)
        #expect(registry.runtime(for: "missing") == nil)
    }

    @Test
    func moduleRegistryExposesTypedFeatureClients() throws {
        struct ProbeFeatureClient: BetterAuthFeatureClient {
            let moduleIdentifier: String
        }

        struct ProbeRuntime: BetterAuthModuleRuntime, BetterAuthFeatureClient {
            let moduleIdentifier: String
            let featureClient: ProbeFeatureClient
        }

        struct ProbeModule: BetterAuthModule {
            let moduleIdentifier: String

            func configure(context _: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
                ProbeRuntime(moduleIdentifier: moduleIdentifier,
                             featureClient: ProbeFeatureClient(moduleIdentifier: moduleIdentifier))
            }

            func makeRequestHooks(context _: BetterAuthModuleContext) -> [any BetterAuthRequestHook] {
                []
            }

            func makeAuthStateListeners(context _: BetterAuthModuleContext) -> [any BetterAuthAuthStateListener] {
                []
            }
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 emptyResponse(for: request)
                             },
                             modules: [ProbeModule(moduleIdentifier: "feature")])

        let runtime = try #require(client.moduleRuntime(for: "feature", as: ProbeRuntime.self))
        let featureClient = try #require(client.featureClient(for: "feature", as: ProbeRuntime.self))
        #expect(runtime.moduleIdentifier == "feature")
        #expect(featureClient.moduleIdentifier == "feature")
        #expect(client.modules.registeredFeatureClientIdentifiers == ["feature"])
    }

    @Test
    func clientAuthLifecycleUsesSessionManagerDirectly() throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 emptyResponse(for: request)
                             })

        let lifecycle = client.authLifecycle
        #expect(type(of: lifecycle) == BetterAuthSessionManager.self)
    }
}
