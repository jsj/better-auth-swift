import BetterAuth
import BetterAuthEmailPassword
import BetterAuthTestHelpers
import Foundation
import Testing

@Suite("Smoke")
struct SmokeTests {
    @Test
    func namespacedAuthClientsUseSameSessionPipeline() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-1",
                                                               userId: "user-1",
                                                               accessToken: "token-1",
                                                               expiresAt: Date().addingTimeInterval(300)),
                                                user: .init(id: "user-1", email: "user@example.com"))
        let listedSession = BetterAuthSessionListEntry(id: "session-1",
                                                       userId: "user-1",
                                                       token: "token-1",
                                                       expiresAt: Date().addingTimeInterval(300),
                                                       createdAt: Date(),
                                                       updatedAt: Date(),
                                                       ipAddress: nil,
                                                       userAgent: nil)
        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/email/sign-in")
            try expect(request.httpMethod == "POST")
            return try response(for: request, statusCode: 200, data: encodeJSON(signedInSession))
        }, .handler { request in
            try expect(request.url?.path == "/api/auth/list-sessions")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
            return try response(for: request, statusCode: 200, data: encodeJSON([listedSession]))
        }])
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "namespace-smoke-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport,
                             modules: [BetterAuthEmailPasswordModule()])

        let session = try await client.requireEmailPassword()
            .signIn(BetterAuthEmailPassword.EmailSignInRequest(email: "user@example.com", password: "password123"))
        #expect(session.session.accessToken == "token-1")
        let current = await client.auth.lifecycle.current()
        #expect(current?.session.id == signedInSession.session.id)
        #expect(current?.session.accessToken == signedInSession.session.accessToken)
        #expect(current?.user.email == signedInSession.user.email)

        let sessions = try await client.auth.sessions.list()
        #expect(sessions.map(\.id) == ["session-1"])
    }

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
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: initialSession),
                                                .response(statusCode: 200, encodable: refreshedSession),
                                                .response(statusCode: 200, encodable: SignOutResult(success: true))])
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "smoke-key")),
                             sessionStore: store,
                             transport: transport,
                             modules: [BetterAuthEmailPasswordModule()])

        let signedIn = try await client.requireEmailPassword()
            .signIn(BetterAuthEmailPassword.EmailSignInRequest(email: "user@example.com", password: "password123"))
        #expect(signedIn.session.accessToken == "token-1")

        let restored = try #require(try await client.auth.loadStoredSession())
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
