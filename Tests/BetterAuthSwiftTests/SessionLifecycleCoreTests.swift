import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct SessionLifecycleCoreTests {
    @Test
    func loadStoredSessionUsesStoreWithoutActorHop() throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let store = InMemorySessionStore()
        try store.saveSession(session, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     })

        let restored = try manager.loadStoredSession()
        #expect(restored == session)
    }

    @Test
    func restoreSessionUsesStore() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let store = InMemorySessionStore()
        try store.saveSession(session, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     })

        let restored = try await manager.restoreSession()
        #expect(restored == session)
    }

    @Test
    func applyRestoredSessionSetsCurrentSession() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     })

        try await manager.applyRestoredSession(session)

        let current = await manager.currentSession()
        #expect(current == session)
    }

    @Test
    func restoreOrRefreshSessionReturnsFreshStoredSessionWithoutNetwork() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let store = InMemorySessionStore()
        try store.saveSession(session, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { _ in
                                         Issue.record("Network should not be used for a fresh stored session")
                                         return emptyResponse(for: URLRequest(url: URL(string: "https://example.com")!))
                                     })

        let restored = try await manager.restoreOrRefreshSession()
        #expect(restored == session)
    }

    @Test
    func refreshSessionIfNeededReturnsCurrentSessionWhenFresh() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { _ in
                                         Issue
                                             .record("Network should not be used for a fresh in-memory session")
                                         return emptyResponse(for: URLRequest(url: URL(string: "https://example.com")!))
                                     })

        try await manager.updateSession(session)
        let current = try await manager.refreshSessionIfNeeded()
        #expect(current == session)
    }

    @Test
    func authorizedRequestRefreshesExpiringSession() async throws {
        let expiring = BetterAuthSession(session: .init(id: "session-1",
                                                        userId: "user-1",
                                                        accessToken: "old-token",
                                                        refreshToken: "refresh-token",
                                                        expiresAt: Date().addingTimeInterval(5)),
                                         user: .init(id: "user-1", email: "test@example.com"))

        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         try expect(request
                                             .value(forHTTPHeaderField: "Authorization") ==
                                             "Bearer old-token")
                                         let data = try encodeJSON(refreshed)
                                         return response(for: request, statusCode: 200, data: data)
                                     })

        try await manager.updateSession(expiring)
        let request = try await manager.authorizedRequest(path: "/api/me")

        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer new-token")
        let current = await manager.currentSession()
        #expect(current?.session.id == refreshed.session.id)
        #expect(current?.session.accessToken == refreshed.session.accessToken)
        #expect(current?.session.refreshToken == refreshed.session.refreshToken)
        #expect(current?.user.id == refreshed.user.id)
        #expect(secondsBetween(current?.session.expiresAt, refreshed.session.expiresAt) <= 1)
    }

    @Test
    func appleNonceHashIsStable() {
        let context = AppleSignInSupport.makeContext(length: 24)
        #expect(AppleSignInSupport
            .sha256("nonce") == "78377b525757b494427f89014f97d79928f3938d14eb51e20fb5dec9834eb304")
        #expect(context.rawNonce.count == 24)
        #expect(context.hashedNonce.count == 64)
    }

    @Test
    func sessionDecodesTokenFieldAsAccessToken() throws {
        let payload = Data("""
        {
          "session": {
            "id": "session-1",
            "userId": "user-1",
            "token": "server-token",
            "refreshToken": "refresh-token",
            "expiresAt": "2026-04-01T21:00:00Z"
          },
          "user": {
            "id": "user-1",
            "email": "test@example.com",
            "name": "Test User"
          }
        }
        """.utf8)

        let session = try BetterAuthCoding.makeDecoder().decode(BetterAuthSession.self, from: payload)

        #expect(session.session.accessToken == "server-token")
        #expect(session.session.refreshToken == "refresh-token")
        #expect(session.user.email == "test@example.com")
    }

    @Test
    func unauthenticatedRequestsIncludeConfiguredOriginHeader() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            return emptyResponse(for: request)
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        _ = try await client.requests.send(path: "/api/auth/sign-in/social",
                                           method: "POST",
                                           requiresAuthentication: false,
                                           retryOnUnauthorized: false)
        let captured = try #require(requests.withLock { $0.first })
        #expect(captured.value(forHTTPHeaderField: "Origin") == "app://snoozy")
    }

    @Test
    func explicitOriginHeaderOverridesConfiguredOrigin() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            return emptyResponse(for: request)
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        _ = try await client.requests.send(path: "/api/auth/sign-in/social",
                                           method: "POST",
                                           headers: ["Origin": "custom://origin"],
                                           requiresAuthentication: false,
                                           retryOnUnauthorized: false)
        let captured = try #require(requests.withLock { $0.first })
        #expect(captured.value(forHTTPHeaderField: "Origin") == "custom://origin")
    }

    @Test
    func authenticatedRequestsRejectCrossOriginAbsoluteURLs() async throws {
        let transport = MockTransport { request in
            Issue.record("Transport should not be invoked for cross-origin request: \(String(describing: request.url))")
            return emptyResponse(for: request)
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1",
                                                                             userId: "user-1",
                                                                             accessToken: "current-token",
                                                                             expiresAt: Date()
                                                                                 .addingTimeInterval(3600)),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        do {
            let _: String? = try await client.requests.sendJSON(path: "https://evil.example.com/api/me")
            Issue.record("Expected cross-origin absolute URL to be rejected")
        } catch let error as BetterAuthError {
            guard case .invalidURL = error else {
                Issue.record("Expected BetterAuthError.invalidURL but got \(error)")
                return
            }
        }
    }

    @Test
    func requestClientRetriesAfterUnauthorized() async throws {
        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 401, jsonObject: ["error": "expired"]),
                                                .response(statusCode: 200, encodable: refreshed),
                                                .response(statusCode: 200, encodable: Response(ok: true))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1",
                                                                             userId: "user-1",
                                                                             accessToken: "old-token",
                                                                             refreshToken: "refresh-token",
                                                                             expiresAt: Date()
                                                                                 .addingTimeInterval(3600)),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        struct Response: Codable, Equatable { let ok: Bool }

        let response: Response = try await client.requests.sendJSON(path: "/api/me")
        #expect(response == Response(ok: true))
    }

    @Test
    func requestClientRetriesOnlyOnceAfterUnauthorized() async throws {
        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 401, jsonObject: ["error": "expired"]),
                                                .response(statusCode: 200, encodable: refreshed),
                                                .response(statusCode: 401,
                                                          jsonObject: ["error": "still unauthorized"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1",
                                                                             userId: "user-1",
                                                                             accessToken: "old-token",
                                                                             refreshToken: "refresh-token",
                                                                             expiresAt: Date()
                                                                                 .addingTimeInterval(3600)),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        struct Response: Codable, Equatable { let ok: Bool }
        await assertRequestFailed(statusCode: 401, message: "{\"error\":\"still unauthorized\"}") {
            let _: Response = try await client.requests.sendJSON(path: "/api/me")
        }
    }

    @Test
    func refreshSessionFallsBackToBearerRefreshWhenNoRefreshTokenExists() async throws {
        let expiring = BetterAuthSession(session: .init(id: "session-1",
                                                        userId: "user-1",
                                                        accessToken: "old-token",
                                                        expiresAt: Date().addingTimeInterval(5)),
                                         user: .init(id: "user-1", email: "test@example.com"))

        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         try expect(request.httpMethod == "POST")
                                         try expect(request.httpBody == nil)
                                         try expect(request
                                             .value(forHTTPHeaderField: "Authorization") ==
                                             "Bearer old-token")
                                         let data = try encodeJSON(refreshed)
                                         return response(for: request, statusCode: 200, data: data)
                                     })

        try await manager.updateSession(expiring)
        let current = try await manager.refreshSession()

        #expect(current.session.id == refreshed.session.id)
        #expect(current.session.accessToken == refreshed.session.accessToken)
        #expect(current.user.id == refreshed.user.id)
        #expect(secondsBetween(current.session.expiresAt, refreshed.session.expiresAt) <= 1)
    }

    @Test
    func restoreOrRefreshSessionRefreshesExpiredStoredSession() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                         userId: "user-1",
                                                         accessToken: "new-token",
                                                         refreshToken: "refresh-token",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(expired, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         try expect(request
                                             .value(forHTTPHeaderField: "Authorization") ==
                                             "Bearer old-token")
                                         let data = try encodeJSON(refreshed)
                                         return response(for: request, statusCode: 200, data: data)
                                     })

        let session = try await manager.restoreOrRefreshSession()
        #expect(session?.session.accessToken == "new-token")
        #expect(try store.loadSession(for: "test-key")?.session.accessToken == "new-token")
    }

    @Test
    func restoreOrRefreshSessionClearsStaleStoredSessionWhenRefreshFails() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(expired, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         return response(for: request,
                                                         statusCode: 401,
                                                         data: Data("{\"error\":\"expired\"}".utf8))
                                     })

        await assertRequestFailed(statusCode: 401, message: "{\"error\":\"expired\"}") {
            _ = try await manager.restoreOrRefreshSession()
        }

        #expect(await manager.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func restoreOrRefreshSessionPreservesStoredSessionOnTransientRefreshFailure() async throws {
        let expiring = BetterAuthSession(session: .init(id: "session-1",
                                                        userId: "user-1",
                                                        accessToken: "live-token",
                                                        refreshToken: "refresh-token",
                                                        expiresAt: Date().addingTimeInterval(5)),
                                         user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(expiring, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         throw URLError(.networkConnectionLost)
                                     })

        do {
            _ = try await manager.restoreOrRefreshSession()
            Issue.record("Expected restoreOrRefreshSession() to fail for transient transport error")
        } catch {
            #expect(error is URLError)
        }

        #expect(await manager.currentSession() == expiring)
        #expect(try store.loadSession(for: "test-key") == expiring)
        await manager.stopAutoRefresh()
    }
}
