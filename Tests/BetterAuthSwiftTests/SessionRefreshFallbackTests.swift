import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth

struct SessionRefreshFallbackTests {
    @Test
    func refreshSessionWithoutRefreshTokenFetchesCurrentSession() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let refreshed = BetterAuthSession(session: .init(id: "session-1",
                                                         userId: "user-1",
                                                         accessToken: "fresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         try expect(request.httpMethod == "GET")
                                         try expect(request.httpBody == nil)
                                         try expect(request.value(forHTTPHeaderField: "Content-Type") == nil)
                                         try expect(request
                                             .value(forHTTPHeaderField: "Authorization") == "Bearer old-token")
                                         return try response(for: request, statusCode: 200, data: encodeJSON(refreshed))
                                     })

        try await manager.updateSession(expired)

        let result = try await manager.refreshSession()
        #expect(result.session.id == refreshed.session.id)
        #expect(result.session.accessToken == refreshed.session.accessToken)
        #expect(result.user == refreshed.user)
        #expect(secondsBetween(result.session.expiresAt, refreshed.session.expiresAt) <= 1)

        let current = await manager.currentSession()
        #expect(current?.session.id == refreshed.session.id)
        #expect(current?.session.accessToken == refreshed.session.accessToken)
        #expect(current?.user == refreshed.user)
        #expect(secondsBetween(current?.session.expiresAt, refreshed.session.expiresAt) <= 1)
    }
}
