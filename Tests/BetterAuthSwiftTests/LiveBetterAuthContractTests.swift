import Foundation
import Testing
@testable import BetterAuth

private enum LiveBetterAuthContract {
    static let environment = ProcessInfo.processInfo.environment
    static let baseURL = environment["BETTER_AUTH_CONTRACT_BASE_URL"].flatMap(URL.init(string:))
    static let email = environment["BETTER_AUTH_CONTRACT_EMAIL"]
    static let password = environment["BETTER_AUTH_CONTRACT_PASSWORD"]
    static let isConfigured = baseURL != nil && email != nil && password != nil
}

struct LiveBetterAuthContractTests {
    @Test(.enabled(if: LiveBetterAuthContract.isConfigured))
    func emailSignInFetchSessionAndSignOutAgainstRealServer() async throws {
        let client = BetterAuthClient(baseURL: try #require(LiveBetterAuthContract.baseURL),
                                      storage: .init(key: "better-auth.contract-test"),
                                      sessionStore: InMemorySessionStore(),
                                      transport: URLSessionTransport())

        let session = try await client.auth.signInWithEmail(.init(email: try #require(LiveBetterAuthContract.email),
                                                                  password: try #require(LiveBetterAuthContract
                                                                      .password)))
        #expect(session.session.accessToken.isEmpty == false)
        #expect(session.user.email == LiveBetterAuthContract.email)

        let fetched = try await client.auth.fetchCurrentSession()
        #expect(fetched.user.id == session.user.id)
        #expect(fetched.session.accessToken.isEmpty == false)

        try await client.auth.signOut(remotely: false)
        #expect(await client.auth.currentSession() == nil)
    }
}
