import BetterAuth
import BetterAuthEmailPassword
import BetterAuthTestHelpers
import Foundation
import Testing

struct EmailUpstreamResponseTests {
    @Test(arguments: [false, true])
    func tokenUserResponsesAreMaterialized(signUp: Bool) async throws {
        let client = makeClient { request in
            if request.url?.path == "/api/auth/get-session" {
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer upstream-token")
                return response(for: request, statusCode: 200,
                                data: Data("""
                                {"session":{"id":"s","userId":"u","token":"upstream-token","expiresAt":"2030-01-01T00:00:00Z"},
                                 "user":{"id":"u","email":"test@example.com"}}
                                """.utf8))
            }
            #expect(request.url?.path == (signUp ? "/api/auth/sign-up/email" : "/api/auth/sign-in/email"))
            return response(for: request, statusCode: 200,
                            data: Data(#"{"token":"upstream-token","user":{"id":"u","email":"test@example.com"}}"#
                                .utf8))
        }
        let emails = try client.requireEmailPassword()
        if signUp {
            guard case .signedIn = try await emails.signUp(.init(email: "test@example.com", password: "password",
                                                                 name: "Test"))
            else {
                Issue.record("Token-bearing sign-up must sign in")
                return
            }
        } else {
            _ = try await emails.signIn(.init(email: "test@example.com", password: "password"))
        }
        #expect(await client.auth.currentSession()?.session.id == "s")
        #expect(await client.auth.currentSession()?.session.expiresAt != nil)
        await client.auth.shutdown()
    }

    @Test
    func nullTokenDoesNotInventVerificationRequirement() async throws {
        let client = makeClient { request in
            #expect(request.url?.path == "/api/auth/sign-up/email")
            return response(for: request, statusCode: 200,
                            data: Data(#"{"token":null,"user":{"id":"u","email":"test@example.com"}}"#.utf8))
        }
        let result = try await client.requireEmailPassword().signUp(.init(email: "test@example.com",
                                                                          password: "password", name: "Test"))
        guard case let .signedUp(user) = result else {
            Issue.record("No token means sign-up succeeded without a session")
            return
        }
        #expect(user.requiresVerification == nil)
        #expect(await client.auth.currentSession() == nil)
        let encoded = try JSONEncoder().encode(result)
        #expect(try JSONDecoder().decode(EmailSignUpResult.self, from: encoded) == result)
    }

    @Test
    func upstreamTwoFactorChallengeIsReported() async throws {
        let client = makeClient { request in
            response(for: request, statusCode: 200, data: Data(#"{"twoFactorRedirect":true}"#.utf8))
        }
        do {
            _ = try await client.requireEmailPassword().signIn(.init(email: "test@example.com", password: "password"))
            Issue.record("Two-factor challenge must not become a session")
        } catch let error as BetterAuthError {
            #expect(error.authErrorCode == .twoFactorRequired)
        }
        #expect(await client.auth.currentSession() == nil)
    }

    @Test
    func malformedSuccessCannotCreateSession() async throws {
        let client = makeClient { request in
            response(for: request, statusCode: 200, data: Data(#"{"token":"token"}"#.utf8))
        }
        await #expect(throws: BetterAuthError.self) {
            try await client.requireEmailPassword().signIn(.init(email: "test@example.com", password: "password"))
        }
        #expect(await client.auth.currentSession() == nil)
    }

    private func makeClient(_ handler: @escaping @Sendable (URLRequest) async throws -> (Data, URLResponse))
        -> BetterAuthClient
    {
        BetterAuthClient(configuration: .init(baseURL: URL(string: "https://example.com")!, autoRefreshToken: false),
                         sessionStore: InMemorySessionStore(), transport: MockTransport(handler: handler),
                         modules: [BetterAuthEmailPasswordModule()])
    }
}
