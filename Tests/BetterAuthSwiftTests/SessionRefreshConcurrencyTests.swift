import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth

struct SessionRefreshConcurrencyTests {
    @Test
    func validSessionReturnsFreshCurrentSessionWithoutNetwork() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "current-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { _ in
                                         Issue.record("Network should not be used for a fresh current session")
                                         return emptyResponse(for: URLRequest(url: URL(string: "https://example.com")!))
                                     })

        try await manager.updateSession(current)

        let result = try await manager.validSession()
        #expect(result == current)
    }

    @Test
    func validSessionRefreshesExpiredCurrentSession() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "new-refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))
        let transport = CountingRefreshTransport(responseSession: refreshed)
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: transport)

        try await manager.updateSession(expired)

        let result = try await manager.validSession()
        #expect(result.session.accessToken == "new-token")
        #expect(await manager.currentSession()?.session.accessToken == "new-token")
        #expect(await transport.requestCount == 1)
    }

    @Test
    func applicationDidBecomeActiveRefreshesExpiredSession() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "new-refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))
        let transport = CountingRefreshTransport(responseSession: refreshed)
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: transport)

        try await manager.updateSession(expired)
        await manager.applicationDidBecomeActive()

        #expect(await manager.currentSession()?.session.accessToken == "new-token")
        #expect(await transport.requestCount == 1)
        await manager.applicationWillResignActive()
    }

    @Test
    func accessTokenChangesEmitsLatestTokenState() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "current-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     })

        try await manager.updateSession(current)

        var iterator = manager.accessTokenChanges.makeAsyncIterator()
        let token = await iterator.next()
        #expect(token == "current-token")
    }

    @Test
    func concurrentRefreshSessionCallsShareOneBackendRequest() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "new-refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))
        let transport = CountingRefreshTransport(responseSession: refreshed)
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: transport)

        try await manager.updateSession(expired)

        async let first = manager.refreshSession()
        async let second = manager.refreshSession()
        async let third = manager.refreshSession()
        let results = try await [first, second, third]

        #expect(results.allSatisfy { $0.session.accessToken == refreshed.session.accessToken })
        #expect(await transport.requestCount == 1)
    }
}

private actor CountingRefreshTransport: BetterAuthTransport {
    private let responseSession: BetterAuthSession
    private(set) var requestCount = 0

    init(responseSession: BetterAuthSession) {
        self.responseSession = responseSession
    }

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        requestCount += 1
        try expect(request.url?.path == "/api/auth/get-session")
        try await Task.sleep(for: .milliseconds(50))
        return try response(for: request, statusCode: 200, data: encodeJSON(responseSession))
    }
}
