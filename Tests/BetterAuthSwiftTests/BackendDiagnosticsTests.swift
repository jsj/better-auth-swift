import BetterAuth
import BetterAuthTestHelpers
import Foundation
import Testing

struct BackendDiagnosticsTests {
    @Test
    func diagnosticsReportHealthyBackendAndAdvertisedFeatures() async throws {
        let metadata = BetterAuthBackendDiagnostics(name: "worker",
                                                    platform: "cloudflare-workers",
                                                    authBasePath: "/api/auth",
                                                    features: [.bearer, .emailPassword, .passkey],
                                                    routes: ["health": "/health"])
        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/health")
            try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            return try response(for: request, statusCode: 200, data: encodeJSON(["ok": true]))
        }, .handler { request in
            try expect(request.url?.path == "/api/better-auth-swift/diagnostics")
            try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            return try response(for: request, statusCode: 200, data: encodeJSON(metadata))
        }])
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let report = await client.diagnostics.check(expectedFeatures: [.bearer, .emailPassword, .passkey])

        #expect(report.isCompatible)
        #expect(report.health.status == .passed)
        #expect(report.backendMetadata.status == .passed)
        #expect(report.advertisedFeatures == [.bearer, .emailPassword, .passkey])
        #expect(report.missingFeatures.isEmpty)
        #expect(report.metadata?.platform == "cloudflare-workers")
    }

    @Test
    func diagnosticsReportMissingExpectedFeatures() async throws {
        let metadata = BetterAuthBackendDiagnostics(features: [.bearer])
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: ["ok": true]),
                                                .response(statusCode: 200, encodable: metadata)])
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let report = await client.diagnostics.check(expectedFeatures: [.bearer, .emailPassword, .passkey])

        #expect(report.isCompatible == false)
        #expect(report.missingFeatures == [.emailPassword, .passkey])
    }

    @Test
    func diagnosticsWarnWhenMetadataEndpointIsMissing() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: ["ok": true]),
                                                .response(statusCode: 404, jsonObject: ["message": "not found"])])
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let report = await client.diagnostics.check()

        #expect(report.health.status == .passed)
        #expect(report.backendMetadata.status == .warning)
        #expect(report.backendMetadata.statusCode == 404)
        #expect(report.metadata == nil)
    }
}
