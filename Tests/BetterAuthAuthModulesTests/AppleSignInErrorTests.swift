import BetterAuth
import BetterAuthAppleSignIn
import BetterAuthTestHelpers
import Foundation
import Testing

struct AppleSignInErrorTests {
    struct FailureCase: Sendable {
        let body: String
        let message: String
        let code: String?
    }

    @Test(arguments: [FailureCase(body: #"{"error":{"code":"internal_error","message":"Database unavailable"}}"#,
                                  message: "Database unavailable", code: "internal_error"),
                      FailureCase(body: #"{"error":"Missing bearer token"}"#, message: "Missing bearer token",
                                  code: nil),
                      FailureCase(body: #"{"message":"Try later","code":"CUSTOM_ERROR"}"#, message: "Try later",
                                  code: "CUSTOM_ERROR"),
                      FailureCase(body: #"{"error":{"code":"SESSION_EXPIRED","message":"expired"}}"#,
                                  message: "The session expired.",
                                  code: "SESSION_EXPIRED"),
                      FailureCase(body: "", message: "Better Auth request failed with status 500.", code: nil),
                      FailureCase(body: "   ", message: "Better Auth request failed with status 500.", code: nil),
                      FailureCase(body: #"{"message":"  "}"#, message: "Better Auth request failed with status 500.",
                                  code: nil),
                      FailureCase(body: #"{"unexpected":"private details"}"#,
                                  message: "Better Auth request failed with status 500.",
                                  code: nil),
                      FailureCase(body: "<html>Proxy failure</html>",
                                  message: "Better Auth request failed with status 500.",
                                  code: nil),
                      FailureCase(body: #"{"error":"#, message: "Better Auth request failed with status 500.",
                                  code: nil)])
    func reportsBackendErrors(_ failure: FailureCase) async throws {
        let requests = Locked(0)
        let client = BetterAuthClient(baseURL: try #require(URL(string: "https://example.com")),
                                      sessionStore: InMemorySessionStore(),
                                      transport: MockTransport { request in
                                          requests.withLock { $0 += 1 }
                                          return try response(for: request, statusCode: 500,
                                                              data: Data(failure.body.utf8))
                                      },
                                      modules: [BetterAuthAppleSignInModule()])
        do {
            _ = try await client.requireAppleSignIn().signIn(.init(token: "identity-token"))
            Issue.record("Expected sign-in to fail")
        } catch let error as BetterAuthError {
            #expect(error.statusCode == 500)
            #expect(error.localizedDescription == failure.message)
            #expect(error.serverError?.code == failure.code)
            if failure.code == "SESSION_EXPIRED" {
                #expect(error.isSessionExpired)
            }
        }
        #expect(requests.withLock { $0 } == 1)
        #expect(await client.auth.currentSession() == nil)
    }
}
