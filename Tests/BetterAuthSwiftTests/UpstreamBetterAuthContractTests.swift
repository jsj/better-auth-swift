import BetterAuth
import BetterAuthEmailPassword
import Foundation
import Testing

private let upstreamURL = ProcessInfo.processInfo.environment["BETTER_AUTH_UPSTREAM_BASE_URL"]
    .flatMap(URL.init(string:))

struct UpstreamBetterAuthContractTests {
    @Test(.enabled(if: upstreamURL != nil))
    func emailLifecycleAndPasswordResetAgainstUnmodifiedHandler() async throws {
        let baseURL = try #require(upstreamURL)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        let transport = URLSessionTransport(session: URLSession(configuration: configuration))
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: .init(baseURL: baseURL, storage: .init(key: "upstream"),
                                                  autoRefreshToken: false,
                                                  requestOrigin: baseURL.absoluteString),
                             sessionStore: store, transport: transport,
                             modules: [BetterAuthEmailPasswordModule()])
        let email = "upstream-\(UUID().uuidString.lowercased())@example.com"
        let password = "ContractPassword123!"
        let emails = try client.requireEmailPassword()
        let result = try await emails.signUp(.init(email: email, password: password, name: "Contract User"))
        guard case let .signedIn(signedUp) = result else {
            Issue.record("Default upstream sign-up should materialize its token/user response")
            return
        }
        #expect(signedUp.user.email == email)
        #expect(signedUp.session.expiresAt != nil)
        try await client.auth.signOut()
        #expect(await client.auth.currentSession() == nil)

        let signedIn = try await emails.signIn(.init(email: email, password: password))
        #expect(signedIn.user.id == signedUp.user.id)
        #expect(try await client.auth.fetchCurrentSession().user.id == signedUp.user.id)
        #expect(try await client.auth.refreshSession().user.id == signedUp.user.id)
        #expect(try await emails.reauthenticate(password: password))
        #expect(await client.auth.currentSession()?.session.accessToken == signedIn.session.accessToken)
        #expect(try await client.auth.listSessions().count == 1)

        #expect(try await emails.requestPasswordReset(.init(email: email)))
        struct ResetCapture: Decodable { let token: String }
        let capture: ResetCapture = try await client.requests.sendJSON(path: "/test/reset-token?email=\(email)",
                                                                       requiresAuthentication: false)
        let newPassword = "UpdatedContractPassword123!"
        #expect(try await emails.resetPassword(.init(token: capture.token, newPassword: newPassword)))
        try await client.auth.signOut()
        let newSession = try await emails.signIn(.init(email: email, password: newPassword))
        #expect(newSession.user.id == signedUp.user.id)
        try await client.auth.signOut()
        // A revoked session is returned as HTTP 200 + null by the standard handler.
        try store.saveSession(newSession, for: "upstream")
        _ = try await client.auth.restoreSession()
        await #expect(throws: BetterAuthError.self) { try await client.auth.fetchCurrentSession() }
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "upstream") == nil)
        await client.auth.shutdown()
    }
}
