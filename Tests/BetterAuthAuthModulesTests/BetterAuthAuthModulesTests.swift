import BetterAuth
import BetterAuthAnonymous
import BetterAuthAppleSignIn
import BetterAuthEmailPassword
import BetterAuthSocialOAuth
import BetterAuthTestHelpers
import BetterAuthUsername
import Foundation
import Testing

@Suite("Auth module registration")
struct BetterAuthAuthModulesTests {
    @Test
    func registersEveryOptionalAuthModule() throws {
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")),
                                      modules: [BetterAuthEmailPasswordModule(),
                                                BetterAuthUsernameModule(),
                                                BetterAuthAnonymousModule(),
                                                BetterAuthSocialOAuthModule(),
                                                BetterAuthAppleSignInModule()])

        _ = try client.requireEmailPassword()
        _ = try client.requireUsername()
        _ = try client.requireAnonymous()
        _ = try client.requireSocialOAuth()
        _ = try client.requireAppleSignIn()
    }

    @Test
    func missingModuleThrowsTypedError() throws {
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")))

        #expect(throws: BetterAuthModuleNotRegisteredError(identifier: "username")) {
            _ = try client.requireUsername()
        }
    }

    @Test
    func extractedModulesOwnRoutesAndApplySessions() async throws {
        let expected = session()
        let paths = Locked(["/custom/email", "/custom/username", "/custom/apple"])
        let transport = MockTransport { request in
            let expectedPath = paths.withLock { $0.removeFirst() }
            try expect(request.url?.path == expectedPath)
            try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            return try response(for: request, statusCode: 200, data: encodeJSON(expected))
        }
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")),
                                      sessionStore: InMemorySessionStore(),
                                      transport: transport,
                                      modules: [BetterAuthEmailPasswordModule(endpoints: .init(signInPath: "/custom/email")),
                                                BetterAuthUsernameModule(endpoints: .init(signInPath: "/custom/username")),
                                                BetterAuthAppleSignInModule(endpoints: .init(signInPath: "/custom/apple"))])

        _ = try await client.requireEmailPassword()
            .signIn(BetterAuthEmailPassword.EmailSignInRequest(email: "user@example.com",
                                                               password: "password"))
        _ = try await client.requireUsername().signIn(BetterAuthUsername.UsernameSignInRequest(username: "user",
                                                                                               password: "password"))
        _ = try await client.requireAppleSignIn()
            .signIn(BetterAuthAppleSignIn.AppleNativeSignInPayload(token: "identity-token"))

        #expect(await client.auth.currentSession() == expected)
        #expect(paths.withLock { $0.isEmpty })
    }

    @Test
    func socialOAuthOwnsCallbackParsing() throws {
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")),
                                      callbackURLSchemes: ["betterauth"],
                                      modules: [BetterAuthSocialOAuthModule(endpoints: .init(genericCallbackPath: "/auth/callback/{providerId}"))])
        let url = try #require(URL(string: "betterauth://host/auth/callback/github?code=code-1&state=state-1"))

        let callback = try client.requireSocialOAuth().parseIncomingURL(url)

        #expect(callback == .init(providerId: "github", code: "code-1", state: "state-1"))
    }

    @Test
    func extractedModulesUseSharedAuthThrottle() async throws {
        let requests = Locked(0)
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")),
                                      authThrottlePolicy: .init(minimumInterval: 60),
                                      sessionStore: InMemorySessionStore(),
                                      transport: MockTransport { request in
                                          requests.withLock { $0 += 1 }
                                          return try response(for: request, statusCode: 200,
                                                              data: encodeJSON(self.session()))
                                      },
                                      modules: [BetterAuthEmailPasswordModule()])
        let email = try client.requireEmailPassword()
        _ = try await email.signIn(.init(email: "user@example.com", password: "password"))

        await #expect(throws: BetterAuthError.self) {
            _ = try await email.signIn(.init(email: "user@example.com", password: "password"))
        }
        #expect(requests.withLock { $0 } == 1)
    }

    private func session() -> BetterAuthSession {
        BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                          user: .init(id: "user-1", email: "user@example.com"))
    }
}
