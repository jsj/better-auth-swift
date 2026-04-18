import BetterAuth
import BetterAuthTestHelpers
import Foundation
import Testing

@Suite("Smoke")
struct SmokeTests {
    @Test
    func signInRestoreRefreshAndSignOutFlow() async throws {
        let initialSession = BetterAuthSession(session: .init(id: "session-1",
                                                              userId: "user-1",
                                                              accessToken: "token-1",
                                                              refreshToken: "refresh-1",
                                                              expiresAt: Date().addingTimeInterval(300)),
                                               user: .init(id: "user-1",
                                                           email: "user@example.com",
                                                           name: "Smoke User"))
        let refreshedSession = BetterAuthSession(session: .init(id: "session-1",
                                                                userId: "user-1",
                                                                accessToken: "token-2",
                                                                refreshToken: "refresh-2",
                                                                expiresAt: Date().addingTimeInterval(600)),
                                                 user: .init(id: "user-1",
                                                             email: "user@example.com",
                                                             name: "Smoke User"))
        let transport = SequencedMockTransport([
            .response(statusCode: 200, encodable: initialSession),
            .response(statusCode: 200, encodable: refreshedSession),
            .response(statusCode: 200, encodable: SignOutResult(success: true))
        ])
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "smoke-key")),
                             sessionStore: store,
                             transport: transport)

        let signedIn = try await client.auth.signInWithEmail(.init(email: "user@example.com", password: "password123"))
        #expect(signedIn.session.accessToken == "token-1")

        let restored = try #require(try client.auth.loadStoredSession())
        #expect(restored.session.accessToken == "token-1")

        let relaunched =
            BetterAuthClient(configuration: client.configuration,
                             sessionStore: store,
                             transport: transport)
        let rehydrated = try await relaunched.auth.restoreSession()
        #expect(rehydrated?.session.accessToken == "token-1")

        let refreshed = try await relaunched.auth.refreshSession()
        #expect(refreshed.session.accessToken == "token-2")

        try await relaunched.auth.signOut(remotely: true)
        #expect(await relaunched.auth.currentSession() == nil)
    }
}
