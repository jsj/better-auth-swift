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
    func clientAuthSessionLifecycleUsesPublicAuthFacade() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 emptyResponse(for: request)
                             })

        let lifecycle = client.authSessionLifecycle
        #expect(type(of: lifecycle) == BetterAuthAuthClient.self)

        let session = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        try await client.auth.updateSession(session)

        #expect(await lifecycle.currentSession() == session)
    }

    @Test
    func moduleRuntimeRequestsUseRegisteredHooks() async throws {
        let observedPaths = Locked<[String]>([])

        struct PathHook: BetterAuthRequestHook {
            let observedPaths: Locked<[String]>

            func prepare(_ request: URLRequest) async throws -> URLRequest {
                observedPaths.withLock { $0.append(request.url?.path ?? "") }
                return request
            }
        }

        struct ProbeRuntime: BetterAuthModuleRuntime {
            let moduleIdentifier = "probe"
            let requests: any BetterAuthRequestPerforming

            func load() async throws {
                _ = try await requests.send(BetterAuthDataRequest(path: "/probe",
                                                                  requiresAuthentication: false))
            }
        }

        struct ProbeModule: BetterAuthModule {
            let moduleIdentifier = "probe"
            let observedPaths: Locked<[String]>

            func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
                ProbeRuntime(requests: context.requestsPerformer)
            }

            func makeRequestHooks(context _: BetterAuthModuleContext) -> [any BetterAuthRequestHook] {
                [PathHook(observedPaths: observedPaths)]
            }
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/probe")
                                 return emptyResponse(for: request)
                             },
                             modules: [ProbeModule(observedPaths: observedPaths)])

        let runtime = try #require(client.moduleRuntime(for: "probe", as: ProbeRuntime.self))
        try await runtime.load()

        #expect(observedPaths.withLock { $0 } == ["/probe"])
    }
}
