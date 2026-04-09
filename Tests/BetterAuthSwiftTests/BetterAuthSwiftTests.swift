import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct BetterAuthSwiftTests {
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
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         #expect(request
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
        let transport = MockTransport { request in
            #expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")
            return response(for: request, statusCode: 200, data: Data("null".utf8))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let _: String? = try await client.requests.sendJSON(path: "/api/auth/sign-in/social",
                                                            method: "POST",
                                                            body: ["provider": "apple"],
                                                            requiresAuthentication: false)
    }

    @Test
    func explicitOriginHeaderOverridesConfiguredOrigin() async throws {
        let transport = MockTransport { request in
            #expect(request.value(forHTTPHeaderField: "Origin") == "custom://origin")
            return response(for: request, statusCode: 200, data: Data("null".utf8))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let _: String? = try await client.requests.sendJSON(path: "/api/auth/sign-in/social",
                                                            method: "POST",
                                                            headers: ["Origin": "custom://origin"],
                                                            body: ["provider": "apple"],
                                                            requiresAuthentication: false)
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
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         #expect(request.httpMethod == "POST")
                                         #expect(request.httpBody == nil)
                                         #expect(request
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
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         #expect(request
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
                                         #expect(request.url?.path == "/api/auth/get-session")
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
                                         #expect(request.url?.path == "/api/auth/get-session")
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
    }

    @Test
    func restoreSessionOnLaunchReturnsDetailedRestoreResult() async throws {
        let stored = BetterAuthSession(session: .init(id: "session-1",
                                                      userId: "user-1",
                                                      accessToken: "token",
                                                      refreshToken: "refresh-token",
                                                      expiresAt: Date().addingTimeInterval(3600)),
                                       user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(stored, for: "test-key")

        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { _ in
                                         Issue.record("Network should not be used for a fresh stored session")
                                         return emptyResponse(for: URLRequest(url: URL(string: "https://example.com")!))
                                     })

        let result = try await manager.restoreSessionOnLaunch()
        #expect(result == .restored(stored, source: .keychain, refresh: .notNeeded))
    }

    @Test
    func restoreSessionOnLaunchReturnsDeferredResultForTransientRefreshFailure() async throws {
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
                                     transport: MockTransport { _ in
                                         throw URLError(.networkConnectionLost)
                                     })

        let result = try await manager.restoreSessionOnLaunch()
        #expect(result == .restored(expiring, source: .keychain, refresh: .deferred))
        #expect(await manager.currentSession() == expiring)
        #expect(try store.loadSession(for: "test-key") == expiring)
    }

    @Test
    func parseIncomingURLRecognizesOAuthMagicLinkAndVerifyEmailRoutes() async throws {
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     })

        let oauthURL =
            try #require(URL(string: "betterauth://host/oauth2/callback/fixture-generic?code=fixture-code&state=fixture-state&iss=https://issuer.example.com"))
        #expect(await manager.parseIncomingURL(oauthURL)
            == .genericOAuth(.init(providerId: "fixture-generic", code: "fixture-code", state: "fixture-state",
                                   issuer: "https://issuer.example.com")))

        let magicURL =
            try #require(URL(string: "https://example.com/api/auth/magic-link/verify?token=magic-token&callbackURL=betterauth://magic/success&errorCallbackURL=betterauth://magic/error"))
        #expect(await manager.parseIncomingURL(magicURL)
            == .magicLink(.init(token: "magic-token", callbackURL: "betterauth://magic/success",
                                errorCallbackURL: "betterauth://magic/error")))

        let verifyEmailURL = try #require(URL(string: "https://example.com/api/auth/verify-email?token=verify-token"))
        #expect(await manager.parseIncomingURL(verifyEmailURL) == .verifyEmail(.init(token: "verify-token")))
    }

    @Test @MainActor
    func authStoreBootstrapUsesDetailedRestoreResult() async throws {
        let stored = BetterAuthSession(session: .init(id: "session-1",
                                                      userId: "user-1",
                                                      accessToken: "token",
                                                      refreshToken: "refresh-token",
                                                      expiresAt: Date().addingTimeInterval(3600)),
                                       user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(stored, for: "test-key")

        let authStore =
            AuthStore(client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                                      storage: .init(key: "test-key")),
                                               sessionStore: store,
                                               transport: MockTransport { request in
                                                   emptyResponse(for: request)
                                               }))

        await authStore.bootstrap()
        #expect(authStore.session == stored)
        #expect(authStore.lastRestoreResult == .restored(stored, source: .keychain, refresh: .notNeeded))
        #expect(authStore.launchState == .authenticated(stored))
        #expect(authStore.statusMessage == "Session restored")
    }

    @Test @MainActor
    func authStoreHandleIncomingURLMaterializesSession() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "magic-session",
                                                               userId: "user-magic",
                                                               accessToken: "magic-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-magic", email: "magic@example.com",
                                                            name: "Magic User"))

        let authStore =
            AuthStore(client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                                               sessionStore: InMemorySessionStore(),
                                               transport: MockTransport { request in
                                                   #expect(request.url?
                                                       .path == "/api/auth/magic-link/verify")
                                                   return try response(for: request,
                                                                       statusCode: 200,
                                                                       data: encodeJSON(SocialSignInTransportResponse(redirect: false,
                                                                                                                      token: verifiedSession
                                                                                                                          .session
                                                                                                                          .accessToken,
                                                                                                                      user: verifiedSession
                                                                                                                          .user,
                                                                                                                      session: verifiedSession)))
                                               }))

        let url = try #require(URL(string: "https://example.com/api/auth/magic-link/verify?token=magic-token-value"))
        await authStore.handleIncomingURL(url)

        #expect(authStore.session?.session.id == verifiedSession.session.id)
        #expect(authStore.session?.session.accessToken == verifiedSession.session.accessToken)
        #expect(authStore.session?.user.email == verifiedSession.user.email)
        #expect(secondsBetween(authStore.session?.session.expiresAt, verifiedSession.session.expiresAt) <= 1)

        guard case let .authenticated(launchSession) = authStore.launchState else {
            Issue.record("Expected authenticated launch state")
            return
        }
        #expect(launchSession.session.id == verifiedSession.session.id)
        #expect(launchSession.session.accessToken == verifiedSession.session.accessToken)
        #expect(launchSession.user.email == verifiedSession.user.email)
        #expect(secondsBetween(launchSession.session.expiresAt, verifiedSession.session.expiresAt) <= 1)
        #expect(authStore.statusMessage == "Magic link handled")
    }

    @Test @MainActor
    func authStoreVerifyMagicLinkMaterializesLaunchState() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "magic-session-direct",
                                                               userId: "user-magic",
                                                               accessToken: "magic-token-direct",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-magic", email: "magic@example.com",
                                                            name: "Magic User"))

        let authStore =
            AuthStore(client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                                               sessionStore: InMemorySessionStore(),
                                               transport: MockTransport { request in
                                                   #expect(request.url?.path == "/api/auth/magic-link/verify")
                                                   return try response(for: request,
                                                                       statusCode: 200,
                                                                       data: encodeJSON(SocialSignInTransportResponse(redirect: false,
                                                                                                                      token: verifiedSession
                                                                                                                          .session
                                                                                                                          .accessToken,
                                                                                                                      user: verifiedSession
                                                                                                                          .user,
                                                                                                                      session: verifiedSession)))
                                               }))

        await authStore.verifyMagicLink(.init(token: "magic-token-direct"))

        #expect(authStore.session?.session.id == verifiedSession.session.id)
        guard case let .authenticated(launchSession) = authStore.launchState else {
            Issue.record("Expected authenticated launch state")
            return
        }
        #expect(launchSession.session.id == verifiedSession.session.id)
        #expect(authStore.statusMessage == "Magic link verified")
    }

    @Test @MainActor
    func authStoreVerifyEmailOTPMaterializesLaunchState() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "otp-session-direct",
                                                               userId: "user-otp",
                                                               accessToken: "otp-token-direct",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp", email: "otp@example.com",
                                                            name: "OTP User"))

        let authStore =
            AuthStore(client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                                               sessionStore: InMemorySessionStore(),
                                               transport: MockTransport { request in
                                                   #expect(request.url?.path == "/api/auth/email-otp/verify-email")
                                                   return try response(for: request,
                                                                       statusCode: 200,
                                                                       data: encodeJSON(SocialSignInTransportResponse(redirect: false,
                                                                                                                      token: verifiedSession
                                                                                                                          .session
                                                                                                                          .accessToken,
                                                                                                                      user: verifiedSession
                                                                                                                          .user,
                                                                                                                      session: verifiedSession)))
                                               }))

        await authStore.verifyEmailOTP(.init(email: "otp@example.com", otp: "123456"))

        #expect(authStore.session?.session.id == verifiedSession.session.id)
        guard case let .authenticated(launchSession) = authStore.launchState else {
            Issue.record("Expected authenticated launch state")
            return
        }
        #expect(launchSession.session.id == verifiedSession.session.id)
        #expect(authStore.statusMessage == "Email OTP verified")
    }

    @Test
    func fetchCurrentSessionDecodesISO8601Expiry() async throws {
        let expiry = "2026-03-29T16:00:00Z"
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         let data = try JSONSerialization
                                             .data(withJSONObject: ["session": ["id": "session-1",
                                                                                "userId": "user-1",
                                                                                "accessToken": "token",
                                                                                "refreshToken": NSNull(),
                                                                                "expiresAt": expiry],
                                                                    "user": ["id": "user-1",
                                                                             "email": "test@example.com",
                                                                             "name": "Test User"]])
                                         return response(for: request, statusCode: 200, data: data)
                                     })

        try await manager.updateSession(BetterAuthSession(session: .init(id: "session-1", userId: "user-1",
                                                                         accessToken: "token"),
                                                          user: .init(id: "user-1", email: "test@example.com")))

        let session = try await manager.fetchCurrentSession()
        #expect(session.session.expiresAt == ISO8601DateFormatter().date(from: expiry))
    }

    @Test
    func fetchCurrentSessionSynchronizesMemoryAndPersistence() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(300)),
                                        user: .init(id: "user-1", email: "old@example.com", name: "Old User"))

        let fetched = BetterAuthSession(session: .init(id: "session-2",
                                                       userId: "user-1",
                                                       accessToken: "new-token",
                                                       refreshToken: "rotated-refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "new@example.com", name: "New User"))

        let store = InMemorySessionStore()
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         #expect(request
                                             .value(forHTTPHeaderField: "Authorization") ==
                                             "Bearer old-token")
                                         return try response(for: request, statusCode: 200,
                                                             data: encodeJSON(fetched))
                                     })

        try await manager.updateSession(current)
        let session = try await manager.fetchCurrentSession()

        #expect(session.session.accessToken == fetched.session.accessToken)
        #expect(session.session.refreshToken == fetched.session.refreshToken)
        #expect(session.user.email == fetched.user.email)
        let inMemory = await manager.currentSession()
        let persisted = try store.loadSession(for: "test-key")
        #expect(inMemory?.session.id == fetched.session.id)
        #expect(inMemory?.session.accessToken == fetched.session.accessToken)
        #expect(inMemory?.session.refreshToken == fetched.session.refreshToken)
        #expect(inMemory?.user.email == fetched.user.email)
        #expect(secondsBetween(inMemory?.session.expiresAt, fetched.session.expiresAt) <= 1)
        #expect(persisted?.session.id == fetched.session.id)
        #expect(persisted?.session.accessToken == fetched.session.accessToken)
        #expect(persisted?.session.refreshToken == fetched.session.refreshToken)
        #expect(persisted?.user.email == fetched.user.email)
        #expect(secondsBetween(persisted?.session.expiresAt, fetched.session.expiresAt) <= 1)
    }

    @Test
    func fetchCurrentSessionPreservesLocalSessionOnTransientFailure() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "live-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(300)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         throw URLError(.notConnectedToInternet)
                                     })

        try await manager.updateSession(current)

        do {
            _ = try await manager.fetchCurrentSession()
            Issue.record("Expected fetchCurrentSession() to fail for transient transport error")
        } catch {
            #expect(error is URLError)
        }

        #expect(await manager.currentSession() == current)
        #expect(try store.loadSession(for: "test-key") == current)
    }

    @Test
    func fetchCurrentSessionClearsStaleSessionWhenUnauthorized() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "dead-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(300)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         return response(for: request,
                                                         statusCode: 401,
                                                         data: Data("{\"error\":\"unauthorized\"}".utf8))
                                     })

        try await manager.updateSession(current)

        await assertRequestFailed(statusCode: 401, message: "{\"error\":\"unauthorized\"}") {
            _ = try await manager.fetchCurrentSession()
        }

        #expect(await manager.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func sessionStorageSharedFactoryUsesProvidedAccessGroup() {
        let storage = BetterAuthConfiguration.SessionStorage.shared(accessGroup: "group.sh.jsj.better-auth")

        #expect(storage.service == "BetterAuth")
        #expect(storage.accessGroup == "group.sh.jsj.better-auth")
        #expect(storage.key == "better-auth.session")
    }

    @Test
    func signOutClearsLocalSessionAfterRemoteRequest() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: SignOutResult(success: true))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1", userId: "user-1",
                                                                             accessToken: "token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        try await client.auth.signOut(remotely: true)
        let current = await client.auth.currentSession()
        #expect(current == nil)
    }

    @Test
    func signOutLocallyClearsSessionWithoutNetwork() async throws {
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: MockTransport { _ in
                                 Issue.record("Local-only sign out should not hit the network")
                                 return emptyResponse(for: URLRequest(url: URL(string: "https://example.com")!))
                             })

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1", userId: "user-1",
                                                                             accessToken: "token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        try await client.auth.signOut(remotely: false)

        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func refreshSessionFailureClearsStaleSessionState() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         return response(for: request,
                                                         statusCode: 401,
                                                         data: Data("{\"error\":\"revoked\"}".utf8))
                                     })

        try await manager.updateSession(expired)

        await assertRequestFailed(statusCode: 401, message: "{\"error\":\"revoked\"}") {
            _ = try await manager.refreshSession()
        }

        #expect(await manager.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func refreshSessionPreservesLocalStateOnTransientFailure() async throws {
        let current = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: MockTransport { request in
                                         #expect(request.url?.path == "/api/auth/get-session")
                                         throw URLError(.networkConnectionLost)
                                     })

        try await manager.updateSession(current)

        do {
            _ = try await manager.refreshSession()
            Issue.record("Expected refreshSession() to fail for transient transport error")
        } catch {
            #expect(error is URLError)
        }

        #expect(await manager.currentSession() == current)
        #expect(try store.loadSession(for: "test-key") == current)
    }

    @Test
    func tokenRotationPersistsAcrossRefreshAndLaterRestore() async throws {
        let expired = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "old-token",
                                                       refreshToken: "old-refresh-token",
                                                       expiresAt: Date().addingTimeInterval(-30)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let rotated = BetterAuthSession(session: .init(id: "session-2",
                                                       userId: "user-1",
                                                       accessToken: "rotated-token",
                                                       refreshToken: "rotated-refresh-token",
                                                       expiresAt: Date().addingTimeInterval(3600)),
                                        user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: rotated),
                                                .response(statusCode: 200,
                                                          encodable: ProtectedResponse(email: "test@example.com"))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    clockSkew: 60),
                             sessionStore: store,
                             transport: transport)

        try await client.auth.updateSession(expired)

        let refreshed = try await client.auth.refreshSession()
        #expect(refreshed.session.id == rotated.session.id)
        #expect(refreshed.session.accessToken == rotated.session.accessToken)
        #expect(refreshed.session.refreshToken == rotated.session.refreshToken)
        #expect(secondsBetween(refreshed.session.expiresAt, rotated.session.expiresAt) <= 1)

        let persisted = try store.loadSession(for: "test-key")
        #expect(persisted?.session.id == rotated.session.id)
        #expect(persisted?.session.accessToken == rotated.session.accessToken)
        #expect(persisted?.session.refreshToken == rotated.session.refreshToken)
        #expect(secondsBetween(persisted?.session.expiresAt, rotated.session.expiresAt) <= 1)

        let rehydratedManager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key"),
                                                                            clockSkew: 60),
                                     sessionStore: store,
                                     transport: transport)

        let restored = try await rehydratedManager.restoreOrRefreshSession()
        #expect(restored?.session.id == rotated.session.id)
        #expect(restored?.session.accessToken == rotated.session.accessToken)
        #expect(restored?.session.refreshToken == rotated.session.refreshToken)
        #expect(secondsBetween(restored?.session.expiresAt, rotated.session.expiresAt) <= 1)

        let request = try await rehydratedManager.authorizedRequest(path: "/api/me")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer rotated-token")
    }

    @Test
    func listSessionsDecodesStableSessionInventoryModels() async throws {
        let now = Date()
        let sessions = [BetterAuthSessionListEntry(id: "session-1",
                                                   userId: "user-1",
                                                   token: "current-token",
                                                   expiresAt: now.addingTimeInterval(600),
                                                   createdAt: now.addingTimeInterval(-120),
                                                   updatedAt: now.addingTimeInterval(-60),
                                                   ipAddress: "127.0.0.1",
                                                   userAgent: "Swift Tests"),
                        BetterAuthSessionListEntry(id: "session-2",
                                                   userId: "user-1",
                                                   token: "other-token",
                                                   expiresAt: now.addingTimeInterval(1200),
                                                   createdAt: now.addingTimeInterval(-300),
                                                   updatedAt: now.addingTimeInterval(-180),
                                                   ipAddress: "127.0.0.2",
                                                   userAgent: "Another Device")]

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/list-sessions")
                                 #expect(request.httpMethod == "GET")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(sessions))
                             })

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        let listed = try await client.auth.listSessions()
        #expect(listed.count == sessions.count)
        #expect(listed.map(\.id) == sessions.map(\.id))
        #expect(listed.map(\.token) == sessions.map(\.token))
        #expect(listed.map(\.userId) == sessions.map(\.userId))
        #expect(listed.map(\.ipAddress) == sessions.map(\.ipAddress))
        #expect(listed.map(\.userAgent) == sessions.map(\.userAgent))
    }

    @Test
    func revokeNonCurrentSessionPreservesLocalCurrentSession() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthStatusResponse(status: true))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let current = BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                       accessToken: "current-token"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        try await client.auth.updateSession(current)

        let revoked = try await client.auth.revokeSession(token: "other-token")
        #expect(revoked)
        let stillCurrent = await client.auth.currentSession()
        #expect(stillCurrent == current)
    }

    @Test
    func defaultEndpointsMatchUpstreamBetterAuthContract() {
        let endpoints = BetterAuthConfiguration.Endpoints()

        #expect(endpoints.currentSessionPath == "/api/auth/get-session")
        #expect(endpoints.sessionRefreshPath == "/api/auth/get-session")
        #expect(endpoints.signOutPath == "/api/auth/sign-out")
        #expect(endpoints.forgotPasswordPath == "/api/auth/forget-password")
        #expect(endpoints.resetPasswordPath == "/api/auth/reset-password")
        #expect(endpoints.sendVerificationEmailPath == "/api/auth/send-verification-email")
        #expect(endpoints.verifyEmailPath == "/api/auth/verify-email")
        #expect(endpoints.changeEmailPath == "/api/auth/change-email")
        #expect(endpoints.updateUserPath == "/api/auth/update-user")
        #expect(endpoints.changePasswordPath == "/api/auth/change-password")
        #expect(endpoints.socialSignInPath == "/api/auth/sign-in/social")
        #expect(endpoints.listLinkedAccountsPath == "/api/auth/list-accounts")
        #expect(endpoints.linkSocialAccountPath == "/api/auth/link-social")
        #expect(endpoints.passkeyRegisterOptionsPath == "/api/auth/passkey/generate-register-options")
        #expect(endpoints.passkeyAuthenticateOptionsPath == "/api/auth/passkey/generate-authenticate-options")
        #expect(endpoints.passkeyRegisterPath == "/api/auth/passkey/verify-registration")
        #expect(endpoints.passkeyAuthenticatePath == "/api/auth/passkey/verify-authentication")
        #expect(endpoints.listPasskeysPath == "/api/auth/passkey/list-user-passkeys")
        #expect(endpoints.updatePasskeyPath == "/api/auth/passkey/update-passkey")
        #expect(endpoints.deletePasskeyPath == "/api/auth/passkey/delete-passkey")
        #expect(endpoints.twoFactorEnablePath == "/api/auth/two-factor/enable")
        #expect(endpoints.twoFactorVerifyTOTPPath == "/api/auth/two-factor/verify-totp")
        #expect(endpoints.twoFactorSendOTPPath == "/api/auth/two-factor/send-otp")
        #expect(endpoints.twoFactorVerifyOTPPath == "/api/auth/two-factor/verify-otp")
        #expect(endpoints.twoFactorVerifyBackupCodePath == "/api/auth/two-factor/verify-backup-code")
        #expect(endpoints.twoFactorGenerateBackupCodesPath == "/api/auth/two-factor/generate-backup-codes")
        #expect(endpoints.listSessionsPath == "/api/auth/list-sessions")
        #expect(endpoints.listDeviceSessionsPath == "/api/auth/multi-session/list-device-sessions")
        #expect(endpoints.setActiveDeviceSessionPath == "/api/auth/multi-session/set-active")
        #expect(endpoints.revokeDeviceSessionPath == "/api/auth/multi-session/revoke")
        #expect(endpoints.sessionJWTPath == "/api/auth/token")
        #expect(endpoints.jwksPath == "/api/auth/jwks")
        #expect(endpoints.revokeSessionPath == "/api/auth/revoke-session")
        #expect(endpoints.revokeSessionsPath == "/api/auth/revoke-sessions")
        #expect(endpoints.revokeOtherSessionsPath == "/api/auth/revoke-other-sessions")
    }

    @Test
    func deviceSessionSurfacesDecodeSetActiveAndRevokeSemantics() async throws {
        let listedSessions = [BetterAuthDeviceSession(session: .init(id: "session-1",
                                                                     userId: "user-1",
                                                                     token: "device-token-1",
                                                                     expiresAt: Date().addingTimeInterval(600)),
                                                      user: .init(id: "user-1", email: "test@example.com",
                                                                  name: "Test User")),
                              BetterAuthDeviceSession(session: .init(id: "session-2",
                                                                     userId: "user-1",
                                                                     token: "device-token-2",
                                                                     expiresAt: Date().addingTimeInterval(1200)),
                                                      user: .init(id: "user-1", email: "test@example.com",
                                                                  name: "Test User"))]

        let activeSession = BetterAuthSession(session: .init(id: "session-2",
                                                             userId: "user-1",
                                                             accessToken: "device-token-2",
                                                             expiresAt: Date().addingTimeInterval(1200)),
                                              user: .init(id: "user-1", email: "test@example.com", name: "Test User"))

        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/multi-session/list-device-sessions")
                #expect(request.httpMethod == "GET")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(listedSessions))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/multi-session/set-active")
                #expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(BetterAuthSetActiveDeviceSessionRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.sessionToken == "device-token-2")
                return try response(for: request, statusCode: 200, data: encodeJSON(activeSession))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/multi-session/revoke")
                #expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(BetterAuthRevokeDeviceSessionRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.sessionToken == "device-token-1")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthStatusResponse(status: true)))
            }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-current", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        let listed = try await client.auth.listDeviceSessions()
        #expect(listed.count == listedSessions.count)
        #expect(listed.map(\.session.id) == listedSessions.map(\.session.id))
        #expect(listed.map(\.session.token) == listedSessions.map(\.session.token))
        #expect(listed.map(\.user.id) == listedSessions.map(\.user.id))

        let setActive = try await client.auth.setActiveDeviceSession(.init(sessionToken: "device-token-2"))
        #expect(setActive.session.accessToken == "device-token-2")
        #expect(await client.auth.currentSession()?.session.accessToken == "device-token-2")
        #expect(try store.loadSession(for: "better-auth.session")?.session.accessToken == "device-token-2")

        let revoked = try await client.auth.revokeDeviceSession(.init(sessionToken: "device-token-1"))
        #expect(revoked)
        #expect(await client.auth.currentSession()?.session.accessToken == "device-token-2")
    }

    @Test
    func jwtAndJWKSDecodeFromWorkerSurfaces() async throws {
        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/token")
                #expect(request.httpMethod == "GET")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthJWT(token: "jwt-token-value")))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/jwks")
                #expect(request.httpMethod == "GET")
                #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
                return response(for: request, statusCode: 200, data: Data("""
                {
                  "keys": [
                    {
                      "kid": "key-1",
                      "kty": "RSA",
                      "alg": "RS256",
                      "use": "sig",
                      "n": "modulus",
                      "e": "AQAB"
                    }
                  ]
                }
                """.utf8))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-current", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        let jwt = try await client.auth.getSessionJWT()
        #expect(jwt.token == "jwt-token-value")

        let jwks = try await client.auth.getJWKS()
        #expect(jwks.keys.count == 1)
        #expect(jwks.keys.first?.keyID == "key-1")
        #expect(jwks.keys.first?.keyType == "RSA")
        #expect(jwks.keys.first?.algorithm == "RS256")
        #expect(jwks.keys.first?.modulus == "modulus")
        #expect(jwks.keys.first?.exponent == "AQAB")
    }

    @Test
    func twoFactorEnableAndTOTPVerificationPersistNativeSession() async throws {
        let current = BetterAuthSession(session: .init(id: "primary-session", userId: "user-2fa",
                                                       accessToken: "primary-token"),
                                        user: .init(id: "user-2fa", email: "twofactor@example.com", name: "2FA User"))
        let store = InMemorySessionStore()
        let nativeSession = BetterAuthSession(session: .init(id: "twofactor-session",
                                                             userId: "user-2fa",
                                                             accessToken: "totp-token",
                                                             expiresAt: Date().addingTimeInterval(3600)),
                                              user: .init(id: "user-2fa", email: "twofactor@example.com",
                                                          name: "2FA User"))

        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/two-factor/enable")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer primary-token")
                let payload = try JSONDecoder().decode(TwoFactorEnableRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.password == "password123")
                #expect(payload.issuer == "Better Auth Swift")
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(TwoFactorEnableResponse(totpURI: "otpauth://totp/Better%20Auth%20Swift:twofactor@example.com?secret=ABC123",
                                                                             backupCodes: ["backup-1", "backup-2"])))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/two-factor/verify-totp")
                let payload = try JSONDecoder().decode(TwoFactorVerifyTOTPRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.code == "123456")
                #expect(payload.trustDevice == true)
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(TwoFactorSessionResponse(token: "totp-token",
                                                                              user: .init(id: "user-2fa",
                                                                                          email: "twofactor@example.com",
                                                                                          name: "2FA User",
                                                                                          twoFactorEnabled: true))))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/get-session")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer totp-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(nativeSession))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.updateSession(current)

        let setup = try await client.auth.enableTwoFactor(.init(password: "password123", issuer: "Better Auth Swift"))
        #expect(setup.totpURI.contains("otpauth://totp/"))
        #expect(setup.backupCodes == ["backup-1", "backup-2"])

        let verified = try await client.auth.verifyTwoFactorTOTP(.init(code: "123456", trustDevice: true))
        #expect(verified.session.accessToken == "totp-token")
        #expect(verified.user.id == "user-2fa")
        #expect(await client.auth.currentSession()?.session.accessToken == "totp-token")
        #expect(try store.loadSession(for: "test-key")?.session.accessToken == "totp-token")
    }

    @Test
    func twoFactorOTPAndRecoveryCodeFlowsPersistSessionAndExposeFailures() async throws {
        let otpSession = BetterAuthSession(session: .init(id: "otp-session",
                                                          userId: "user-2fa",
                                                          accessToken: "otp-token",
                                                          expiresAt: Date().addingTimeInterval(3600)),
                                           user: .init(id: "user-2fa", email: "twofactor@example.com",
                                                       name: "2FA User"))
        let recoverySession = BetterAuthSession(session: .init(id: "recovery-session",
                                                               userId: "user-2fa",
                                                               accessToken: "recovery-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-2fa", email: "twofactor@example.com",
                                                            name: "2FA User"))
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: TwoFactorChallengeStatusResponse(status: true)),
                                                                .response(statusCode: 200,
                                                                          encodable: TwoFactorSessionResponse(token: "otp-token",
                                                                                                              user: .init(id: "user-2fa",
                                                                                                                          email: "twofactor@example.com",
                                                                                                                          name: "2FA User",
                                                                                                                          twoFactorEnabled: true))),
                                                                .response(statusCode: 200,
                                                                          encodable: otpSession),
                                                                .response(statusCode: 200,
                                                                          encodable: TwoFactorSessionResponse(token: "recovery-token",
                                                                                                              user: .init(id: "user-2fa",
                                                                                                                          email: "twofactor@example.com",
                                                                                                                          name: "2FA User",
                                                                                                                          twoFactorEnabled: true))),
                                                                .response(statusCode: 200,
                                                                          encodable: recoverySession),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "INVALID_BACKUP_CODE",
                                                                                       "message": "Invalid backup code"]),
                                                                .response(statusCode: 401,
                                                                          jsonObject: ["code": "INVALID_BACKUP_CODE",
                                                                                       "message": "Invalid backup code"])]))

        let sent = try await client.auth.sendTwoFactorOTP(.init(trustDevice: true))
        #expect(sent)

        let otpVerified = try await client.auth.verifyTwoFactorOTP(.init(code: "654321", trustDevice: true))
        #expect(otpVerified.session.accessToken == "otp-token")
        #expect(await client.auth.currentSession()?.session.accessToken == "otp-token")

        let recoveryVerified = try await client.auth.verifyTwoFactorRecoveryCode(.init(code: "backup-1"))
        #expect(recoveryVerified.session.accessToken == "recovery-token")
        #expect(await client.auth.currentSession()?.session.accessToken == "recovery-token")
        #expect(try store.loadSession(for: "test-key")?.session.accessToken == "recovery-token")

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "INVALID_BACKUP_CODE",
                                                                      "message": "Invalid backup code"])
        {
            _ = try await client.auth.verifyTwoFactorRecoveryCode(.init(code: "backup-invalid"))
        }

        await assertRequestFailedJSON(statusCode: 401, expectedJSON: ["code": "INVALID_BACKUP_CODE",
                                                                      "message": "Invalid backup code"])
        {
            _ = try await client.auth.verifyTwoFactorRecoveryCode(.init(code: "backup-reused"))
        }
    }

    @Test
    func passkeyAuthenticateOptionsWorkWhileSignedOut() async throws {
        let expected = PasskeyAuthenticationOptions(challenge: "discoverable-challenge",
                                                    timeout: 60000,
                                                    rpId: "127.0.0.1",
                                                    allowCredentials: nil,
                                                    userVerification: "preferred")

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?
                                     .path == "/api/auth/passkey/generate-authenticate-options")
                                 #expect(request.httpMethod == "GET")
                                 #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
                                 return try response(for: request, statusCode: 200, data: encodeJSON(expected))
                             })

        let options = try await client.auth.passkeyAuthenticateOptions()
        #expect(options == expected)
    }

    @Test
    func passkeyRegistrationAndManagementFlowsUseAuthenticatedRoutes() async throws {
        let createdAt = Date().addingTimeInterval(-30)
        let current = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "passkey-token"),
                                        user: .init(id: "user-1", email: "passkey@example.com"))
        let options = PasskeyRegistrationOptions(challenge: "register-challenge",
                                                 rp: .init(name: "Better Auth Swift", id: "127.0.0.1"),
                                                 user: .init(id: "user-handle", name: "passkey@example.com",
                                                             displayName: "passkey@example.com"),
                                                 pubKeyCredParams: [.init(type: "public-key", alg: -7)],
                                                 timeout: 60000,
                                                 excludeCredentials: [.init(id: "credential-id", type: "public-key",
                                                                            transports: ["internal"])],
                                                 authenticatorSelection: .init(authenticatorAttachment: "platform",
                                                                               requireResidentKey: nil,
                                                                               residentKey: "preferred",
                                                                               userVerification: "preferred"),
                                                 attestation: "none")
        let createdPasskey = Passkey(id: "passkey-1",
                                     name: "MacBook",
                                     publicKey: "public-key",
                                     userId: "user-1",
                                     credentialID: "credential-id",
                                     counter: 0,
                                     deviceType: "singleDevice",
                                     backedUp: true,
                                     transports: "internal",
                                     createdAt: createdAt,
                                     aaguid: "aaguid-1")
        let renamedPasskey = Passkey(id: "passkey-1",
                                     name: "Renamed MacBook",
                                     publicKey: "public-key",
                                     userId: "user-1",
                                     credentialID: "credential-id",
                                     counter: 1,
                                     deviceType: "singleDevice",
                                     backedUp: true,
                                     transports: "internal",
                                     createdAt: createdAt,
                                     aaguid: "aaguid-1")

        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/passkey/generate-register-options")
                #expect(request.url?.query?.contains("name=MacBook") == true)
                #expect(request.url?.query?.contains("authenticatorAttachment=platform") == true)
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(options))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/passkey/verify-registration")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                let payload = try JSONDecoder().decode(PasskeyRegistrationRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.name == "MacBook")
                #expect(payload.response.id == "credential-id")
                return try response(for: request, statusCode: 200, data: encodeJSON(createdPasskey))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/passkey/list-user-passkeys")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                return try response(for: request, statusCode: 200, data: encodeJSON([createdPasskey]))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/passkey/update-passkey")
                let payload = try JSONDecoder().decode(UpdatePasskeyRequest.self, from: try #require(request.httpBody))
                #expect(payload.id == "passkey-1")
                #expect(payload.name == "Renamed MacBook")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(UpdatePasskeyResponse(passkey: renamedPasskey)))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/passkey/delete-passkey")
                let payload = try JSONDecoder().decode(DeletePasskeyRequest.self, from: try #require(request.httpBody))
                #expect(payload.id == "passkey-1")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthStatusResponse(status: true)))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.updateSession(current)

        let registerOptions = try await client.auth.passkeyRegistrationOptions(.init(name: "MacBook",
                                                                                     authenticatorAttachment: "platform"))
        #expect(registerOptions == options)

        let created = try await client.auth.registerPasskey(.init(response: .init(id: "credential-id",
                                                                                  rawId: "credential-raw",
                                                                                  response: .init(clientDataJSON: "client-data",
                                                                                                  attestationObject: "attestation",
                                                                                                  transports: ["internal"])),
                                                                  name: "MacBook"))
        #expect(created.id == createdPasskey.id)
        #expect(created.name == createdPasskey.name)
        #expect(created.publicKey == createdPasskey.publicKey)
        #expect(created.userId == createdPasskey.userId)
        #expect(created.credentialID == createdPasskey.credentialID)
        #expect(created.counter == createdPasskey.counter)
        #expect(created.deviceType == createdPasskey.deviceType)
        #expect(created.backedUp == createdPasskey.backedUp)
        #expect(created.transports == createdPasskey.transports)
        #expect(created.aaguid == createdPasskey.aaguid)
        #expect(secondsBetween(created.createdAt, createdPasskey.createdAt) <= 1)

        let listed = try await client.auth.listPasskeys()
        #expect(listed.count == 1)
        #expect(listed.first?.id == createdPasskey.id)
        #expect(listed.first?.name == createdPasskey.name)
        #expect(listed.first?.credentialID == createdPasskey.credentialID)
        #expect(secondsBetween(listed.first?.createdAt, createdPasskey.createdAt) <= 1)

        let updated = try await client.auth.updatePasskey(.init(id: "passkey-1", name: "Renamed MacBook"))
        #expect(updated.id == renamedPasskey.id)
        #expect(updated.name == renamedPasskey.name)
        #expect(updated.counter == renamedPasskey.counter)
        #expect(updated.credentialID == renamedPasskey.credentialID)
        #expect(secondsBetween(updated.createdAt, renamedPasskey.createdAt) <= 1)

        let deleted = try await client.auth.deletePasskey(.init(id: "passkey-1"))
        #expect(deleted)
    }

    @Test
    func passkeyAuthenticationPersistsSessionAndSupportsRestore() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "passkey-session",
                                                               userId: "user-1",
                                                               accessToken: "passkey-access-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-1", email: "passkey@example.com",
                                                            name: "Passkey User"))
        let protectedPayload = ProtectedResponse(email: "passkey@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                   token: signedInSession
                                                                                                       .session
                                                                                                       .accessToken,
                                                                                                   user: signedInSession
                                                                                                       .user,
                                                                                                   session: signedInSession)),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.authenticateWithPasskey(.init(response: .init(id: "credential-id",
                                                                                          rawId: "credential-raw",
                                                                                          response: .init(clientDataJSON: "client-data",
                                                                                                          authenticatorData: "auth-data",
                                                                                                          signature: "signature",
                                                                                                          userHandle: "user-handle"))))

        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.user.email == signedInSession.user.email)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == signedInSession.session.accessToken)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.accessToken == signedInSession.session.accessToken)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func passkeyVerificationFailuresRemainExplicitForContinuityBreaks() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 400,
                                                                          jsonObject: ["code": "CHALLENGE_NOT_FOUND",
                                                                                       "message": "Challenge not found"]),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "AUTHENTICATION_FAILED",
                                                                                       "message": "Authentication failed"]),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "FAILED_TO_VERIFY_REGISTRATION",
                                                                                       "message": "Failed to verify registration"])]))

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "CHALLENGE_NOT_FOUND",
                                                                      "message": "Challenge not found"])
        {
            _ = try await client.auth.authenticateWithPasskey(.init(response: .init(id: "credential-id",
                                                                                    rawId: "credential-raw",
                                                                                    response: .init(clientDataJSON: "missing-challenge"))))
        }

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "AUTHENTICATION_FAILED",
                                                                      "message": "Authentication failed"])
        {
            _ = try await client.auth.authenticateWithPasskey(.init(response: .init(id: "credential-id",
                                                                                    rawId: "credential-raw",
                                                                                    response: .init(clientDataJSON: "wrong-origin"))))
        }

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "FAILED_TO_VERIFY_REGISTRATION",
                                                                      "message": "Failed to verify registration"])
        {
            _ = try await client.auth.registerPasskey(.init(response: .init(id: "credential-id",
                                                                            rawId: "credential-raw",
                                                                            response: .init(clientDataJSON: "stale-registration",
                                                                                            attestationObject: "attestation"))))
        }
    }

    @Test
    func socialSignInReturnsAuthorizationURLWithoutPersistingSession() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/sign-in/social")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")
            let payload = try JSONDecoder().decode(SocialSignInRequest.self, from: try #require(request.httpBody))
            #expect(payload.provider == "google")
            #expect(payload.disableRedirect == true)

            return try response(for: request,
                                statusCode: 200,
                                data: encodeJSON(SocialAuthorizationResponse(url: "https://accounts.google.com/o/oauth2/v2/auth?state=test",
                                                                             redirect: false)))
        }

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signInWithSocial(SocialSignInRequest(provider: "google",
                                                                                disableRedirect: true))

        guard case let .authorizationURL(authURL) = result else {
            Issue.record("Expected authorization URL result")
            return
        }

        #expect(authURL.redirect == false)
        #expect(authURL.url.contains("accounts.google.com"))
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "better-auth.session") == nil)
    }

    @Test
    func anonymousSignInMaterializesAndPersistsNativeSession() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200, jsonObject: ["token": "anon-token",
                                                                                        "user": ["id": "anon-user",
                                                                                                 "email": "temp@anon.example.com",
                                                                                                 "name": "Anonymous"]]),
                                                .response(statusCode: 200,
                                                          jsonObject: ["session": ["id": "session-anon",
                                                                                   "userId": "anon-user",
                                                                                   "accessToken": "anon-token",
                                                                                   "expiresAt": ISO8601DateFormatter()
                                                                                       .string(from: Date()
                                                                                           .addingTimeInterval(3600))],
                                                                       "user": ["id": "anon-user",
                                                                                "email": "temp@anon.example.com",
                                                                                "name": "Anonymous"]]),
                                                .response(statusCode: 200, jsonObject: ["status": true])])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInAnonymously()
        #expect(session.user.id == "anon-user")
        #expect(session.session.accessToken == "anon-token")
        #expect(await client.auth.currentSession() == session)
        #expect(try store.loadSession(for: "better-auth.session") == session)

        let deleted = try await client.auth.deleteAnonymousUser()
        #expect(deleted == true)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "better-auth.session") == nil)
    }

    @Test
    func genericOAuthInitiationAndCompletionMaterializeNativeSession() async throws {
        let store = InMemorySessionStore()
        let transport = MockTransport { request in
            if request.url?.path == "/api/auth/sign-in/oauth2" {
                #expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(GenericOAuthSignInRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.providerId == "fixture-generic")
                #expect(payload.disableRedirect == true)
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(GenericOAuthAuthorizationResponse(url: "https://fixture-oauth.example.com/oauth/authorize?state=fixture-state",
                                                                                       redirect: false)))
            }

            if request.url?.path == "/api/auth/oauth2/callback/fixture-generic" {
                #expect(request.httpMethod == "GET")
                let components = URLComponents(url: try #require(request.url), resolvingAgainstBaseURL: true)
                #expect(components?.queryItems?.first(where: { $0.name == "code" })?.value == "fixture-code")
                #expect(components?.queryItems?.first(where: { $0.name == "state" })?.value == "fixture-state")
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(BetterAuthSession(session: .init(id: "session-oauth",
                                                                                      userId: "oauth-user",
                                                                                      accessToken: "oauth-token"),
                                                                       user: .init(id: "oauth-user",
                                                                                   email: "oauth@example.com",
                                                                                   name: "OAuth User"))))
            }

            return emptyResponse(for: request)
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: store,
                             transport: transport)

        let authURL = try await client.auth.beginGenericOAuth(GenericOAuthSignInRequest(providerId: "fixture-generic",
                                                                                        callbackURL: "betterauth://oauth/success",
                                                                                        disableRedirect: true))
        #expect(authURL.redirect == false)
        #expect(authURL.url.contains("fixture-oauth.example.com"))

        let session = try await client.auth
            .completeGenericOAuth(GenericOAuthCallbackRequest(providerId: "fixture-generic",
                                                              code: "fixture-code",
                                                              state: "fixture-state"))
        #expect(session.session.accessToken == "oauth-token")
        #expect(session.user.email == "oauth@example.com")
        #expect(await client.auth.currentSession() == session)
        #expect(try store.loadSession(for: "better-auth.session") == session)
    }

    @Test
    func listLinkedAccountsDecodesStableModels() async throws {
        let linkedAccounts = [LinkedAccount(id: "account-row-1",
                                            providerId: "google",
                                            createdAt: Date().addingTimeInterval(-120),
                                            updatedAt: Date().addingTimeInterval(-60),
                                            accountId: "google-user-1",
                                            userId: "user-1",
                                            scopes: ["openid", "email"])]

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/list-accounts")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 return try response(for: request, statusCode: 200,
                                                     data: encodeJSON(linkedAccounts))
                             })

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "linked@example.com")))

        let result = try await client.auth.listLinkedAccounts()
        #expect(result.count == linkedAccounts.count)
        #expect(result.first?.id == linkedAccounts.first?.id)
        #expect(result.first?.providerId == linkedAccounts.first?.providerId)
        #expect(result.first?.accountId == linkedAccounts.first?.accountId)
        #expect(result.first?.userId == linkedAccounts.first?.userId)
        #expect(result.first?.scopes == linkedAccounts.first?.scopes)
    }

    @Test
    func genericOAuthLinkUsesAuthenticatedRoute() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/oauth2/link")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let payload = try JSONDecoder().decode(GenericOAuthSignInRequest.self,
                                                                        from: try #require(request.httpBody))
                                 #expect(payload.providerId == "fixture-generic")
                                 #expect(payload.callbackURL == "betterauth://oauth/success")
                                 #expect(payload.disableRedirect == true)
                                 return try response(for: request,
                                                     statusCode: 200,
                                                     data: encodeJSON(GenericOAuthAuthorizationResponse(url: "https://fixture-oauth.example.com/oauth/authorize?state=link-state",
                                                                                                        redirect: true)))
                             })

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "linked@example.com")))

        let result = try await client.auth.linkGenericOAuth(GenericOAuthSignInRequest(providerId: "fixture-generic",
                                                                                      callbackURL: "betterauth://oauth/success",
                                                                                      disableRedirect: true))

        #expect(result.redirect == true)
        #expect(result.url.contains("link-state"))
    }

    @Test
    func genericOAuthLinkCallbackReconcilesExistingSessionWhenCallbackDoesNotRotateBearer() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                               accessToken: "current-token"),
                                                user: .init(id: "user-1", email: "current@example.com",
                                                            name: "Current User"))
        let reconciledSession = BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                 accessToken: "current-token"),
                                                  user: .init(id: "user-1", email: "current@example.com",
                                                              name: "Current User", username: "linked-user",
                                                              displayUsername: "Linked User"))
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/oauth2/callback/fixture-generic")
                                 #expect(request.httpMethod == "GET")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let components = URLComponents(url: try #require(request.url),
                                                                resolvingAgainstBaseURL: true)
                                 #expect(components?.queryItems?.first(where: { $0.name == "code" })?
                                     .value == "fixture-code")
                                 #expect(components?.queryItems?.first(where: { $0.name == "state" })?
                                     .value == "fixture-state")
                                 return try response(for: request, statusCode: 200,
                                                     data: encodeJSON(reconciledSession))
                             })

        try await client.auth.updateSession(existingSession)

        let session = try await client.auth
            .completeGenericOAuth(GenericOAuthCallbackRequest(providerId: "fixture-generic",
                                                              code: "fixture-code",
                                                              state: "fixture-state"))

        #expect(session == reconciledSession)
        #expect(await client.auth.currentSession() == reconciledSession)
        #expect(try store.loadSession(for: "better-auth.session") == reconciledSession)
    }

    @Test
    func linkSocialAccountDecodesSuccessResponse() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/link-social")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let payload = try JSONDecoder().decode(LinkSocialAccountRequest.self,
                                                                        from: try #require(request.httpBody))
                                 #expect(payload.provider == "google")
                                 #expect(payload.idToken?.token == "valid-google-token")
                                 return try response(for: request,
                                                     statusCode: 200,
                                                     data: encodeJSON(LinkSocialAccountResponse(url: "",
                                                                                                redirect: false,
                                                                                                status: true)))
                             })

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "linked@example.com")))

        let result = try await client.auth.linkSocialAccount(LinkSocialAccountRequest(provider: "google",
                                                                                      idToken: SocialIDTokenPayload(token: "valid-google-token")))

        #expect(result.redirect == false)
        #expect(result.status == true)
    }

    @Test
    func linkSocialAccountPreservesPolicyFailureSemantics() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 401,
                                                          jsonObject: ["code": "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
                                                                       "message": "Account not linked - different emails not allowed"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "linked@example.com")))

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.linkSocialAccount(LinkSocialAccountRequest(provider: "google",
                                                                                 idToken: SocialIDTokenPayload(token: "cross-user-token")))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 401, sourceLocation: location)
            #expect(response?.code == "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", sourceLocation: location)
            #expect(response?.message == "Account not linked - different emails not allowed", sourceLocation: location)
        }
    }

    @Test
    func revokeCurrentSessionClearsLocalCurrentSession() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthStatusResponse(status: true))])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let current = BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                       accessToken: "current-token"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        try await client.auth.updateSession(current)

        let revoked = try await client.auth.revokeSession(token: "current-token")
        #expect(revoked)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func revokeOtherSessionsKeepsCurrentSessionAvailable() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthStatusResponse(status: true))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let current = BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                       accessToken: "current-token"),
                                        user: .init(id: "user-1", email: "test@example.com"))
        try await client.auth.updateSession(current)

        let revoked = try await client.auth.revokeOtherSessions()
        #expect(revoked)
        #expect(await client.auth.currentSession() == current)
    }

    @Test
    func revokeAllSessionsClearsLocalCurrentSession() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthStatusResponse(status: true))])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        let revoked = try await client.auth.revokeSessions()
        #expect(revoked)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func requestPasswordResetUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/forget-password")
            #expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(ForgotPasswordRequest.self, from: try #require(request.httpBody))
            #expect(payload.email == "reset@example.com")
            #expect(payload.redirectTo == "https://app.example.com/reset")

            return try response(for: request, statusCode: 200, data: encodeJSON(BetterAuthStatusResponse(status: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let status = try await client.auth.requestPasswordReset(ForgotPasswordRequest(email: "reset@example.com",
                                                                                      redirectTo: "https://app.example.com/reset"))

        #expect(status)
    }

    @Test
    func resetPasswordUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/reset-password")
            #expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(ResetPasswordRequest.self, from: try #require(request.httpBody))
            #expect(payload.token == "reset-token")
            #expect(payload.newPassword == "new-password-123")

            return try response(for: request, statusCode: 200, data: encodeJSON(BetterAuthStatusResponse(status: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let status = try await client.auth.resetPassword(ResetPasswordRequest(token: "reset-token",
                                                                              newPassword: "new-password-123"))

        #expect(status)
    }

    @Test
    func sendVerificationEmailUsesConfiguredEndpointAndCurrentBearer() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/send-verification-email")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(SendVerificationEmailRequest.self,
                                                   from: try #require(request.httpBody))
            #expect(payload.email == nil)
            #expect(payload.callbackURL == "https://app.example.com/verify")

            return try response(for: request, statusCode: 200, data: encodeJSON(BetterAuthStatusResponse(status: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "verify@example.com")))

        let status = try await client.auth
            .sendVerificationEmail(SendVerificationEmailRequest(callbackURL: "https://app.example.com/verify"))

        #expect(status)
    }

    @Test
    func verifyEmailWithoutAutoSignInDoesNotPersistSession() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/verify-email")
            #expect(request.httpMethod == "GET")
            #expect(request.httpBody == nil)
            #expect(request.url?.query == "token=verify-token")
            let body = """
            {"status":true,"session":null}
            """.data(using: .utf8)!
            return response(for: request, statusCode: 200, data: body)
        }

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.verifyEmail(VerifyEmailRequest(token: "verify-token"))

        #expect(result == .verified)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func verifyEmailWithAutoSignInPersistsNativeSession() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "verified-session",
                                                               userId: "user-1",
                                                               accessToken: "verified-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-1", email: "verified@example.com",
                                                            name: "Verified User"))
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/verify-email")
            #expect(request.httpMethod == "GET")
            #expect(request.httpBody == nil)
            #expect(request.url?.query == "token=verify-token")
            return try response(for: request,
                                statusCode: 200,
                                data: encodeJSON(SocialSignInTransportResponse(redirect: false,
                                                                               token: verifiedSession.session
                                                                                   .accessToken,
                                                                               user: verifiedSession.user,
                                                                               session: verifiedSession)))
        }

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.verifyEmail(VerifyEmailRequest(token: "verify-token"))

        guard case let .signedIn(session) = result else {
            Issue.record("Expected signed-in verify-email result")
            return
        }

        #expect(session.session.id == verifiedSession.session.id)
        #expect(session.session.accessToken == verifiedSession.session.accessToken)
        #expect(session.user.email == verifiedSession.user.email)
        #expect(secondsBetween(session.session.expiresAt, verifiedSession.session.expiresAt) <= 1)
        let current = await client.auth.currentSession()
        #expect(current?.session.id == verifiedSession.session.id)
        #expect(current?.session.accessToken == verifiedSession.session.accessToken)
        #expect(current?.user.email == verifiedSession.user.email)
        #expect(secondsBetween(current?.session.expiresAt, verifiedSession.session.expiresAt) <= 1)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == verifiedSession.session.id)
        #expect(stored?.session.accessToken == verifiedSession.session.accessToken)
        #expect(stored?.user.email == verifiedSession.user.email)
        #expect(secondsBetween(stored?.session.expiresAt, verifiedSession.session.expiresAt) <= 1)
    }

    @Test
    func changeEmailUsesConfiguredEndpointAndCurrentBearer() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/change-email")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(ChangeEmailRequest.self, from: try #require(request.httpBody))
            #expect(payload.newEmail == "next@example.com")
            #expect(payload.callbackURL == "https://app.example.com/settings")

            return try response(for: request, statusCode: 200, data: encodeJSON(BetterAuthStatusResponse(status: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "current@example.com")))

        let status = try await client.auth.changeEmail(ChangeEmailRequest(newEmail: "next@example.com",
                                                                          callbackURL: "https://app.example.com/settings"))

        #expect(status)
    }

    @Test
    func changePasswordSurfacesBackendPolicyFailures() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 400,
                                                          jsonObject: ["code": "PASSWORD_TOO_SHORT",
                                                                       "message": "Password is too short"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "current-session", userId: "user-1",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-1", email: "signin@example.com")))

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.changePassword(ChangePasswordRequest(currentPassword: "old-password",
                                                                           newPassword: "short"))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 400, sourceLocation: location)
            #expect(response?.code == "PASSWORD_TOO_SHORT", sourceLocation: location)
            #expect(response?.message == "Password is too short", sourceLocation: location)
        }
    }

    @Test
    func changePasswordWithRevokeOtherSessionsMaterializesReplacementSession() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-1",
                                                               accessToken: "current-token",
                                                               refreshToken: "refresh-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-1",
                                                            email: "user@example.com",
                                                            name: "Current Name",
                                                            username: "current_user",
                                                            displayUsername: "Current User"))

        let replacementSession = BetterAuthSession(session: .init(id: "replacement-session",
                                                                  userId: "user-1",
                                                                  accessToken: "rotated-token",
                                                                  refreshToken: nil,
                                                                  expiresAt: Date().addingTimeInterval(7200)),
                                                   user: .init(id: "user-1",
                                                               email: "user@example.com",
                                                               name: "Updated Name",
                                                               username: "current_user",
                                                               displayUsername: "Current User"))

        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/change-password")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                let payload = try JSONDecoder().decode(ChangePasswordRequest.self, from: try #require(request.httpBody))
                #expect(payload.revokeOtherSessions == true)

                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(ChangePasswordResponse(token: "rotated-token",
                                                                            user: .init(id: "user-1",
                                                                                        email: "user@example.com",
                                                                                        name: "Updated Name"))))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/get-session")
                #expect(request.httpMethod == "GET")
                #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer rotated-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(replacementSession))
            }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.changePassword(.init(currentPassword: "old-password",
                                                                newPassword: "new-password-123",
                                                                revokeOtherSessions: true))

        #expect(result.token == "rotated-token")
        #expect(result.user.name == "Updated Name")
        let current = await client.auth.currentSession()
        #expect(current?.session.id == "replacement-session")
        #expect(current?.session.accessToken == "rotated-token")
        #expect(current?.session.refreshToken == nil)
        #expect(secondsBetween(current?.session.expiresAt, replacementSession.session.expiresAt) <= 1)
        #expect(current?.user.name == "Updated Name")
        #expect(current?.user.username == "current_user")
        #expect(current?.user.displayUsername == "Current User")
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == "replacement-session")
        #expect(stored?.session.accessToken == "rotated-token")
        #expect(stored?.session.refreshToken == nil)
        #expect(stored?.user.username == "current_user")
        #expect(stored?.user.displayUsername == "Current User")
    }

    @Test
    func emailSignUpPersistsNativeSessionAndSupportsRestore() async throws {
        let signedUpSession = BetterAuthSession(session: .init(id: "session-sign-up",
                                                               userId: "user-1",
                                                               accessToken: "signup-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-1", email: "signup@example.com",
                                                            name: "Sign Up User"))

        let protectedPayload = ProtectedResponse(email: "signup@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: signedUpSession),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signUpWithEmail(.init(email: "signup@example.com", password: "password123",
                                                                 name: "Sign Up User"))
        guard case let .signedIn(session) = result else {
            Issue.record("Expected session-bearing sign-up result")
            return
        }
        #expect(session.session.id == signedUpSession.session.id)
        #expect(session.session.accessToken == signedUpSession.session.accessToken)
        #expect(session.user.email == signedUpSession.user.email)
        #expect(secondsBetween(session.session.expiresAt, signedUpSession.session.expiresAt) <= 1)

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == signedUpSession.session.id)
        #expect(stored?.session.accessToken == signedUpSession.session.accessToken)
        #expect(stored?.user.email == signedUpSession.user.email)
        #expect(secondsBetween(stored?.session.expiresAt, signedUpSession.session.expiresAt) <= 1)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.id == signedUpSession.session.id)
        #expect(restored?.session.accessToken == signedUpSession.session.accessToken)
        #expect(restored?.user.email == signedUpSession.user.email)
        #expect(secondsBetween(restored?.session.expiresAt, signedUpSession.session.expiresAt) <= 1)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func emailSignUpReturnsExplicitVerificationHeldResultWithoutPersistingSession() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: VerificationHeldEmailSignUp(requiresVerification: true,
                                                                                                 user: .init(id: "user-held",
                                                                                                             email: "held@example.com",
                                                                                                             name: "Held User")))])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signUpWithEmail(.init(email: "held@example.com", password: "password123",
                                                                 name: "Held User"))

        guard case let .verificationHeld(held) = result else {
            Issue.record("Expected verification-held sign-up result")
            return
        }

        #expect(held.requiresVerification)
        #expect(held.user?.id == "user-held")
        #expect(held.user?.email == "held@example.com")
        #expect(held.user?.name == "Held User")
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func emailSignUpReturnsExplicitSignedUpResultWhenAutoSignInIsDisabled() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: SuccessfulEmailSignUp(requiresVerification: false,
                                                                                           user: .init(id: "user-signed-up",
                                                                                                       email: "signed-up@example.com",
                                                                                                       name: "Signed Up User",
                                                                                                       username: "signed_up_user",
                                                                                                       displayUsername: "Signed Up User")))])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signUpWithEmail(.init(email: "signed-up@example.com",
                                                                 password: "password123", name: "Signed Up User"))

        guard case let .signedUp(signedUp) = result else {
            Issue.record("Expected signed-up result when auto sign-in is disabled")
            return
        }

        #expect(signedUp.requiresVerification == false)
        #expect(signedUp.user?.id == "user-signed-up")
        #expect(signedUp.user?.email == "signed-up@example.com")
        #expect(signedUp.user?.name == "Signed Up User")
        #expect(signedUp.user?.username == "signed_up_user")
        #expect(signedUp.user?.displayUsername == "Signed Up User")
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func emailSignUpNormalizesDuplicateEmailIntoEnumerationSafeSignedUpResult() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          jsonObject: ["requiresVerification": false,
                                                                       "user": NSNull()])])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signUpWithEmail(EmailSignUpRequest(email: "duplicate@example.com",
                                                                              password: "password123",
                                                                              name: "Duplicate User"))

        guard case let .signedUp(signedUp) = result else {
            Issue.record("Expected enumeration-safe signed-up result for duplicate email")
            return
        }

        #expect(signedUp.requiresVerification == false)
        #expect(signedUp.user == nil)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func emailSignInPersistsNativeSessionAndSupportsRestore() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-sign-in",
                                                               userId: "user-1",
                                                               accessToken: "signin-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-1", email: "signin@example.com",
                                                            name: "Sign In User"))

        let protectedPayload = ProtectedResponse(email: "signin@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: signedInSession),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInWithEmail(.init(email: "signin@example.com", password: "password123"))
        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.user.email == signedInSession.user.email)
        #expect(secondsBetween(session.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == signedInSession.session.id)
        #expect(stored?.session.accessToken == signedInSession.session.accessToken)
        #expect(stored?.user.email == signedInSession.user.email)
        #expect(secondsBetween(stored?.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.id == signedInSession.session.id)
        #expect(restored?.session.accessToken == signedInSession.session.accessToken)
        #expect(restored?.user.email == signedInSession.user.email)
        #expect(secondsBetween(restored?.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func emailSignInPreservesExplicitUnverifiedEmailFailure() async throws {
        let failurePayload = ["code": "EMAIL_NOT_VERIFIED",
                              "message": "Email not verified"]
        let transport = SequencedMockTransport([.response(statusCode: 403,
                                                          jsonObject: failurePayload)])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.signInWithEmail(EmailSignInRequest(email: "unverified@example.com",
                                                                         password: "password123"))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 403, sourceLocation: location)
            #expect(response?.code == failurePayload["code"], sourceLocation: location)
            #expect(response?.message == failurePayload["message"], sourceLocation: location)
        }
        #expect(await client.auth.currentSession() == nil)
    }

    @Test
    func usernameAvailabilityUsesConfiguredEndpointAndPreservesNormalizationSemantics() async throws {
        let transport = SequencedMockTransport([.handler { request in
                #expect(request.url?.path == "/api/auth/is-username-available")
                #expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(UsernameAvailabilityRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.username == "PRIORITY_USER")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(UsernameAvailabilityResponse(available: false)))
            },
            .handler { request in
                #expect(request.url?.path == "/api/auth/is-username-available")
                let payload = try JSONDecoder().decode(UsernameAvailabilityRequest.self,
                                                       from: try #require(request.httpBody))
                #expect(payload.username == "fresh_user")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(UsernameAvailabilityResponse(available: true)))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let unavailable = try await client.auth.isUsernameAvailable(.init(username: "PRIORITY_USER"))
        #expect(unavailable == false)

        let available = try await client.auth.isUsernameAvailable(.init(username: "fresh_user"))
        #expect(available == true)
    }

    @Test
    func usernameSignInPersistsNativeSessionAndSupportsRestore() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-username-sign-in",
                                                               userId: "user-username",
                                                               accessToken: "username-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-username",
                                                            email: "username@example.com",
                                                            name: "Username User",
                                                            username: "custom_user",
                                                            displayUsername: "Custom_User"))

        let protectedPayload = ProtectedResponse(email: "username@example.com", username: "custom_user")
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: signedInSession),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInWithUsername(.init(username: "Custom_User", password: "password123"))
        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.user.email == signedInSession.user.email)
        #expect(session.user.username == "custom_user")
        #expect(session.user.displayUsername == "Custom_User")
        #expect(secondsBetween(session.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == signedInSession.session.id)
        #expect(stored?.session.accessToken == signedInSession.session.accessToken)
        #expect(stored?.user.username == "custom_user")
        #expect(stored?.user.displayUsername == "Custom_User")

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.id == signedInSession.session.id)
        #expect(restored?.session.accessToken == signedInSession.session.accessToken)
        #expect(restored?.user.username == "custom_user")
        #expect(restored?.user.displayUsername == "Custom_User")

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func usernameSignInPreservesInvalidCredentialFailure() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 401,
                                                                          jsonObject: ["code": "INVALID_USERNAME_OR_PASSWORD",
                                                                                       "message": "Invalid username or password"])]))

        await assertRequestFailedJSON(statusCode: 401, expectedJSON: ["code": "INVALID_USERNAME_OR_PASSWORD",
                                                                      "message": "Invalid username or password"])
        {
            _ = try await client.auth.signInWithUsername(.init(username: "missing_user", password: "wrong-password"))
        }
    }

    @Test
    func emailSignUpPreservesUsernameFieldsAndNormalizationSemantics() async throws {
        let signedUpSession = BetterAuthSession(session: .init(id: "session-sign-up-username",
                                                               userId: "user-username",
                                                               accessToken: "signup-username-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-username",
                                                            email: "username-signup@example.com",
                                                            name: "Username Sign Up",
                                                            username: "custom_user",
                                                            displayUsername: "Custom_User"))

        let transport = SequencedMockTransport([.handler { request in
            #expect(request.url?.path == "/api/auth/email/sign-up")
            let payload = try JSONDecoder().decode(EmailSignUpRequest.self, from: try #require(request.httpBody))
            #expect(payload.username == "Custom_User")
            #expect(payload.displayUsername == nil)
            return try response(for: request, statusCode: 200, data: encodeJSON(signedUpSession))
        }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.signUpWithEmail(.init(email: "username-signup@example.com",
                                                                 password: "password123",
                                                                 name: "Username Sign Up",
                                                                 username: "Custom_User"))

        guard case let .signedIn(session) = result else {
            Issue.record("Expected username sign-up to materialize a session")
            return
        }

        #expect(session.user.username == "custom_user")
        #expect(session.user.displayUsername == "Custom_User")
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.user.username == "custom_user")
        #expect(stored?.user.displayUsername == "Custom_User")
    }

    @Test
    func updateUserPreservesUsernameFieldsAndCurrentSessionState() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-username",
                                                               accessToken: "current-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-username",
                                                            email: "username@example.com",
                                                            name: "Original Name",
                                                            username: "original_user",
                                                            displayUsername: "Original User"))
        let updatedUser = BetterAuthSession.User(id: "user-username",
                                                 email: "username@example.com",
                                                 name: "Updated Name",
                                                 username: "priority_user",
                                                 displayUsername: "Priority Display Name")

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/update-user")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(UpdateUserRequest.self, from: try #require(request.httpBody))
            #expect(payload.username == "Priority_User")
            #expect(payload.displayUsername == "Priority Display Name")
            #expect(payload.name == "Updated Name")

            return try response(for: request, statusCode: 200,
                                data: encodeJSON(UpdateUserResponse(status: true, user: updatedUser)))
        }

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.updateUser(.init(name: "Updated Name", username: "Priority_User",
                                                            displayUsername: "Priority Display Name"))

        #expect(result.status)
        #expect(result.user?.username == "priority_user")
        #expect(result.user?.displayUsername == "Priority Display Name")
        let current = await client.auth.currentSession()
        #expect(current?.user.username == "priority_user")
        #expect(current?.user.displayUsername == "Priority Display Name")
        #expect(current?.user.name == "Updated Name")
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.user.username == "priority_user")
        #expect(stored?.user.displayUsername == "Priority Display Name")
    }

    @Test
    func updateUserPreservesDuplicateUsernameFailureSemantics() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 400,
                                                                          jsonObject: ["code": "USERNAME_IS_ALREADY_TAKEN",
                                                                                       "message": "Username is already taken"])]))

        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "existing-session",
                                                                             userId: "user-username",
                                                                             accessToken: "current-token"),
                                                              user: .init(id: "user-username",
                                                                          email: "username@example.com")))

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "USERNAME_IS_ALREADY_TAKEN",
                                                                      "message": "Username is already taken"])
        {
            _ = try await client.auth.updateUser(.init(username: "Duplicate_User"))
        }
    }

    @Test
    func magicLinkRequestEncodesNativeContextFields() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/sign-in/magic-link")
            #expect(request.httpMethod == "POST")
            let payload = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            #expect(payload?["email"] as? String == "magic@example.com")
            #expect(payload?["name"] as? String == "Magic User")
            #expect(payload?["callbackURL"] as? String == "betterauth://magic/success")
            #expect(payload?["newUserCallbackURL"] as? String == "betterauth://magic/new")
            #expect(payload?["errorCallbackURL"] as? String == "betterauth://magic/error")
            let metadata = payload?["metadata"] as? [String: String]
            #expect(metadata?["source"] == "ios")
            #expect(metadata?["campaign"] == "spring")

            return try response(for: request, statusCode: 200, data: encodeJSON(BetterAuthStatusResponse(status: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let status = try await client.auth.requestMagicLink(MagicLinkRequest(email: "magic@example.com",
                                                                             name: "Magic User",
                                                                             callbackURL: "betterauth://magic/success",
                                                                             newUserCallbackURL: "betterauth://magic/new",
                                                                             errorCallbackURL: "betterauth://magic/error",
                                                                             metadata: ["source": "ios",
                                                                                        "campaign": "spring"]))

        #expect(status)
    }

    @Test
    func magicLinkVerificationPersistsSessionAndSupportsRestore() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "magic-session",
                                                               userId: "user-magic",
                                                               accessToken: "magic-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-magic", email: "magic@example.com",
                                                            name: "Magic User"))
        let protectedPayload = ProtectedResponse(email: "magic@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                   token: verifiedSession
                                                                                                       .session
                                                                                                       .accessToken,
                                                                                                   user: verifiedSession
                                                                                                       .user,
                                                                                                   session: verifiedSession)),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let result = try await client.auth.verifyMagicLink(MagicLinkVerifyRequest(token: "magic-token-value"))

        guard case let .signedIn(session) = result else {
            Issue.record("Expected signed-in magic-link verification result")
            return
        }

        #expect(session.session.id == verifiedSession.session.id)
        #expect(session.session.accessToken == verifiedSession.session.accessToken)
        #expect(session.user.email == verifiedSession.user.email)
        #expect(secondsBetween(session.session.expiresAt, verifiedSession.session.expiresAt) <= 1)

        let current = await client.auth.currentSession()
        #expect(current?.session.id == verifiedSession.session.id)
        #expect(current?.session.accessToken == verifiedSession.session.accessToken)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.id == verifiedSession.session.id)
        #expect(stored?.session.accessToken == verifiedSession.session.accessToken)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.id == verifiedSession.session.id)
        #expect(restored?.session.accessToken == verifiedSession.session.accessToken)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func magicLinkVerificationFailureRemainsInspectable() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 400,
                                                          encodable: MagicLinkVerificationResult
                                                              .failure(MagicLinkFailure(error: "EXPIRED_TOKEN",
                                                                                        status: 302,
                                                                                        redirectURL: "betterauth://magic/error?error=EXPIRED_TOKEN")))])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.verifyMagicLink(MagicLinkVerifyRequest(token: "expired-token",
                                                                             callbackURL: "betterauth://magic/success",
                                                                             errorCallbackURL: "betterauth://magic/error"))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, message, _, _) {
            #expect(statusCode == 400, sourceLocation: location)
            #expect(message?.contains("EXPIRED_TOKEN") == true, sourceLocation: location)
        }

        #expect(await client.auth.currentSession() == nil)
    }

    @Test
    func emailOTPRequestUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/email-otp/send-verification-otp")
            #expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(EmailOTPRequest.self, from: try #require(request.httpBody))
            #expect(payload.email == "otp@example.com")
            #expect(payload.type == .signIn)

            return try response(for: request, statusCode: 200, data: encodeJSON(EmailOTPRequestResponse(success: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let success = try await client.auth.requestEmailOTP(.init(email: "otp@example.com", type: .signIn))
        #expect(success)
    }

    @Test
    func emailOTPSignInPersistsNativeSessionAndSupportsRestore() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "otp-session",
                                                               userId: "user-otp",
                                                               accessToken: "otp-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp", email: "otp@example.com", name: "OTP User"))

        let protectedPayload = ProtectedResponse(email: "otp@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                   token: signedInSession
                                                                                                       .session
                                                                                                       .accessToken,
                                                                                                   user: signedInSession
                                                                                                       .user,
                                                                                                   session: signedInSession)),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "123456",
                                                                     name: "OTP User"))
        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.user.email == signedInSession.user.email)

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == signedInSession.session.accessToken)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.accessToken == signedInSession.session.accessToken)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func emailOTPSignInPreservesStableFailureContracts() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 400,
                                                                          jsonObject: ["code": "INVALID_OTP",
                                                                                       "message": "Invalid OTP"]),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "OTP_EXPIRED",
                                                                                       "message": "OTP expired"]),
                                                                .response(statusCode: 403,
                                                                          jsonObject: ["code": "TOO_MANY_ATTEMPTS",
                                                                                       "message": "Too many attempts"])]))

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "INVALID_OTP",
                                                                      "message": "Invalid OTP"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "111111"))
        }

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "OTP_EXPIRED",
                                                                      "message": "OTP expired"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "222222"))
        }

        await assertRequestFailedJSON(statusCode: 403, expectedJSON: ["code": "TOO_MANY_ATTEMPTS",
                                                                      "message": "Too many attempts"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "333333"))
        }
    }

    @Test
    func emailOTPVerifyUpdatesCurrentUserWithoutPersistingNewSession() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-otp",
                                                               accessToken: "existing-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp",
                                                            email: "otp@example.com",
                                                            name: "OTP User",
                                                            username: "otp_user",
                                                            displayUsername: "OTP User"))
        let verifiedUser = BetterAuthSession.User(id: "user-otp",
                                                  email: "otp@example.com",
                                                  name: "Verified OTP User")

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: EmailOTPVerifyResult
                                                                              .verified(verifiedUser))]))

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.verifyEmailOTP(.init(email: "otp@example.com", otp: "123456"))

        guard case let .verified(user) = result else {
            Issue.record("Expected verified email OTP result")
            return
        }

        #expect(user == verifiedUser)
        let current = await client.auth.currentSession()
        #expect(current?.session.accessToken == existingSession.session.accessToken)
        #expect(current?.user.name == "Verified OTP User")
        #expect(current?.user.username == "otp_user")
        #expect(current?.user.displayUsername == "OTP User")
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == existingSession.session.accessToken)
        #expect(stored?.user.name == "Verified OTP User")
        #expect(stored?.user.username == "otp_user")
        #expect(stored?.user.displayUsername == "OTP User")
    }

    @Test
    func emailOTPVerifyForDifferentUserDoesNotOverwriteCurrentSession() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-current",
                                                               accessToken: "existing-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-current",
                                                            email: "current@example.com",
                                                            name: "Current User",
                                                            username: "current_user",
                                                            displayUsername: "Current User"))
        let verifiedUser = BetterAuthSession.User(id: "user-other",
                                                  email: "other@example.com",
                                                  name: "Other User")

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: EmailOTPVerifyResult
                                                                              .verified(verifiedUser))]))

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.verifyEmailOTP(.init(email: "other@example.com", otp: "123456"))

        guard case let .verified(user) = result else {
            Issue.record("Expected verified email OTP result")
            return
        }

        #expect(user == verifiedUser)
        let current = await client.auth.currentSession()
        #expect(current == existingSession)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored == existingSession)
    }

    func emailOTPVerifyWithAutoSignInPersistsNativeSession() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "otp-verified-session",
                                                               userId: "user-otp",
                                                               accessToken: "verified-otp-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp", email: "otp@example.com",
                                                            name: "Verified OTP User"))

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: URL(string: "https://example.com")!,
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                                   token: verifiedSession
                                                                                                                       .session
                                                                                                                       .accessToken,
                                                                                                                   user: verifiedSession
                                                                                                                       .user,
                                                                                                                   session: verifiedSession))]))

        let result = try await client.auth.verifyEmailOTP(.init(email: "otp@example.com", otp: "654321"))

        guard case let .signedIn(session) = result else {
            Issue.record("Expected signed-in email OTP verify result")
            return
        }

        #expect(session.session.accessToken == verifiedSession.session.accessToken)
        let current = await client.auth.currentSession()
        #expect(current?.session.accessToken == verifiedSession.session.accessToken)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == verifiedSession.session.accessToken)
    }

    @Test
    func phoneOTPRequestUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/phone-number/send-otp")
            #expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(PhoneOTPRequest.self, from: try #require(request.httpBody))
            #expect(payload.phoneNumber == "+15555550123")

            return try response(for: request, statusCode: 200,
                                data: encodeJSON(PhoneOTPRequestResponse(message: "code sent")))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let success = try await client.auth.requestPhoneOTP(.init(phoneNumber: "+15555550123"))
        #expect(success)
    }

    @Test
    func phoneNumberVerifyUsesAuthenticatedRouteAndUpdatesReturnedUserWhenUpdatingPhoneNumber() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "phone-session",
                                                               userId: "user-phone",
                                                               accessToken: "phone-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-phone", email: "phone@example.com",
                                                            name: "Phone User"))

        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/phone-number/verify")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer phone-token")
            let payload = try JSONDecoder().decode(PhoneOTPVerifyRequest.self, from: try #require(request.httpBody))
            #expect(payload.phoneNumber == "+15555550123")
            #expect(payload.code == "123456")
            #expect(payload.disableSession == true)
            #expect(payload.updatePhoneNumber == true)

            return try response(for: request,
                                statusCode: 200,
                                data: encodeJSON(PhoneOTPVerifyResponse(status: true,
                                                                        user: BetterAuthSession.User(id: "user-phone",
                                                                                                     email: "phone@example.com",
                                                                                                     name: "Phone User"))))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(existingSession)
        let verified = try await client.auth.verifyPhoneNumber(PhoneOTPVerifyRequest(phoneNumber: "+15555550123",
                                                                                     code: "123456",
                                                                                     disableSession: true,
                                                                                     updatePhoneNumber: true))
        #expect(verified == PhoneOTPVerifyResponse(status: true,
                                                   user: BetterAuthSession.User(id: "user-phone",
                                                                                email: "phone@example.com",
                                                                                name: "Phone User")))
        #expect(await client.auth.currentSession()?.session.accessToken == "phone-token")
    }

    @Test
    func phoneNumberVerifyUsesPublicRouteWhenNotUpdatingPhoneNumber() async throws {
        let transport = MockTransport { request in
            #expect(request.url?.path == "/api/auth/phone-number/verify")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            let payload = try JSONDecoder().decode(PhoneOTPVerifyRequest.self, from: try #require(request.httpBody))
            #expect(payload.phoneNumber == "+15555550123")
            #expect(payload.code == "123456")
            #expect(payload.updatePhoneNumber == nil)

            return try response(for: request,
                                statusCode: 200,
                                data: encodeJSON(PhoneOTPVerifyResponse(status: true,
                                                                        user: BetterAuthSession.User(id: "user-phone",
                                                                                                     email: "phone@example.com",
                                                                                                     name: "Phone User"))))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let verified = try await client.auth.verifyPhoneNumber(PhoneOTPVerifyRequest(phoneNumber: "+15555550123",
                                                                                     code: "123456"))
        #expect(verified.status)
        #expect(verified.user?.id == "user-phone")
    }

    @Test
    func phoneNumberVerifyMaterializesSessionWhenSessionCreationIsEnabled() async throws {
        let fetchedSession = BetterAuthSession(session: .init(id: "phone-session",
                                                              userId: "user-phone",
                                                              accessToken: "phone-token",
                                                              expiresAt: Date().addingTimeInterval(3600)),
                                               user: .init(id: "user-phone", email: "phone@example.com",
                                                           name: "Phone User"))

        let transport = SequencedMockTransport([.response(statusCode: 200, jsonObject: ["status": true,
                                                                                        "token": "phone-token",
                                                                                        "user": ["id": "user-phone",
                                                                                                 "email": "phone@example.com",
                                                                                                 "name": "Phone User",
                                                                                                 "phoneNumber": "+15555550123",
                                                                                                 "phoneNumberVerified": true]]),
                                                .response(statusCode: 200, encodable: fetchedSession)])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let verified = try await client.auth.verifyPhoneNumber(PhoneOTPVerifyRequest(phoneNumber: "+15555550123",
                                                                                     code: "123456"))
        #expect(verified.status)
        #expect(verified.token == "phone-token")
        #expect(verified.user?.id == "user-phone")
        #expect(await client.auth.currentSession()?.session.accessToken == "phone-token")
    }

    @Test
    func phoneNumberSignInMaterializesPersistedNativeSession() async throws {
        let fetchedSession = BetterAuthSession(session: .init(id: "phone-session",
                                                              userId: "user-phone",
                                                              accessToken: "phone-token",
                                                              expiresAt: Date().addingTimeInterval(3600)),
                                               user: .init(id: "user-phone", email: nil, name: nil))

        let protectedPayload = ProtectedResponse(email: "phone@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200, jsonObject: ["token": "phone-token",
                                                                                        "user": ["id": "user-phone",
                                                                                                 "twoFactorEnabled": false]]),
                                                .response(statusCode: 200, encodable: fetchedSession),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInWithPhoneOTP(.init(phoneNumber: "+15555550123",
                                                                     password: "password123"))
        #expect(session.session.accessToken == "phone-token")
        #expect(await client.auth.currentSession()?.session.accessToken == "phone-token")
        #expect(try store.loadSession(for: "test-key")?.session.accessToken == "phone-token")

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.accessToken == "phone-token")

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func phoneOTPSignInPreservesStableFailureContracts() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 400,
                                                                          jsonObject: ["code": "INVALID_OTP",
                                                                                       "message": "Invalid OTP"]),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "OTP_EXPIRED",
                                                                                       "message": "OTP expired"])]))

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "INVALID_OTP",
                                                                      "message": "Invalid OTP"])
        {
            _ = try await client.auth.signInWithPhoneOTP(.init(phoneNumber: "+15555550123", password: "password111"))
        }

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "OTP_EXPIRED",
                                                                      "message": "OTP expired"])
        {
            _ = try await client.auth.signInWithPhoneOTP(.init(phoneNumber: "+15555550123", password: "password222"))
        }
    }

    @Test
    func appleSignInUsesConfiguredNativeRouteAndPersistsSession() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-apple-sign-in",
                                                               userId: "user-apple",
                                                               accessToken: "apple-token",
                                                               refreshToken: "apple-refresh-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-apple", email: "apple@example.com",
                                                            name: "Apple User"))

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    endpoints: .init(nativeAppleSignInPath: "/api/auth/apple/native"),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/apple/native")
                                 #expect(request.httpMethod == "POST")
                                 #expect(request
                                     .value(forHTTPHeaderField: "Content-Type") == "application/json")
                                 #expect(request.value(forHTTPHeaderField: "Authorization") == nil)
                                 #expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")

                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 #expect(payload.token == "identity-token")
                                 #expect(payload.nonce == "raw-nonce")
                                 #expect(payload.authorizationCode == "auth-code")
                                 #expect(payload.email == "apple@example.com")
                                 #expect(payload.givenName == "Apple")
                                 #expect(payload.familyName == "User")

                                 return try response(for: request, statusCode: 200,
                                                     data: encodeJSON(signedInSession))
                             })

        let session = try await client.auth.signInWithApple(.init(token: "identity-token",
                                                                  nonce: "raw-nonce",
                                                                  authorizationCode: "auth-code",
                                                                  email: "apple@example.com",
                                                                  givenName: "Apple",
                                                                  familyName: "User"))

        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.session.refreshToken == signedInSession.session.refreshToken)
        #expect(session.user.id == signedInSession.user.id)
        #expect(session.user.email == signedInSession.user.email)
        #expect(session.user.name == signedInSession.user.name)
        #expect(secondsBetween(session.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let persisted = try store.loadSession(for: "test-key")
        #expect(persisted?.session.id == signedInSession.session.id)
        #expect(persisted?.session.accessToken == signedInSession.session.accessToken)
        #expect(persisted?.session.refreshToken == signedInSession.session.refreshToken)
        #expect(persisted?.user.id == signedInSession.user.id)
        #expect(persisted?.user.email == signedInSession.user.email)
        #expect(persisted?.user.name == signedInSession.user.name)
        #expect(secondsBetween(persisted?.session.expiresAt, signedInSession.session.expiresAt) <= 1)
    }

    @Test
    func appleSignInAllowsRepeatAuthorizationWithoutFirstUseProfileHints() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-repeat-apple-sign-in",
                                                               userId: "user-apple",
                                                               accessToken: "apple-repeat-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-apple", email: "apple@example.com",
                                                            name: "Apple User"))

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    endpoints: .init(nativeAppleSignInPath: "/api/auth/apple/native"),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/apple/native")
                                 #expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")
                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 #expect(payload.token == "repeat-identity-token")
                                 #expect(payload.nonce == "repeat-raw-nonce")
                                 #expect(payload.email == nil)
                                 #expect(payload.givenName == nil)
                                 #expect(payload.familyName == nil)
                                 #expect(payload.authorizationCode == nil)
                                 return try response(for: request, statusCode: 200,
                                                     data: encodeJSON(signedInSession))
                             })

        let session = try await client.auth.signInWithApple(.init(token: "repeat-identity-token",
                                                                  nonce: "repeat-raw-nonce"))

        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.session.refreshToken == signedInSession.session.refreshToken)
        #expect(session.user.id == signedInSession.user.id)
        #expect(session.user.email == signedInSession.user.email)
        #expect(session.user.name == signedInSession.user.name)
        #expect(secondsBetween(session.session.expiresAt, signedInSession.session.expiresAt) <= 1)
        let persisted = try store.loadSession(for: "test-key")
        #expect(persisted?.session.id == signedInSession.session.id)
        #expect(persisted?.session.accessToken == signedInSession.session.accessToken)
        #expect(persisted?.session.refreshToken == signedInSession.session.refreshToken)
        #expect(persisted?.user.id == signedInSession.user.id)
        #expect(persisted?.user.email == signedInSession.user.email)
        #expect(persisted?.user.name == signedInSession.user.name)
        #expect(secondsBetween(persisted?.session.expiresAt, signedInSession.session.expiresAt) <= 1)
    }

    @Test
    func appleSignInUsesConfiguredNativeRouteWithoutSocialFallback() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "session-apple-native-route",
                                                               userId: "user-apple",
                                                               accessToken: "native-route-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-apple", email: "apple@example.com",
                                                            name: "Apple User"))

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key"),
                                                                    endpoints: .init(nativeAppleSignInPath: "/api/auth/custom-apple/native",
                                                                                     socialSignInPath: "/api/auth/sign-in/social"),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/custom-apple/native")
                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 #expect(payload.token == "identity-token")
                                 return try response(for: request, statusCode: 200,
                                                     data: encodeJSON(signedInSession))
                             })

        let session = try await client.auth.signInWithApple(.init(token: "identity-token",
                                                                  nonce: "raw-nonce",
                                                                  email: "apple@example.com",
                                                                  givenName: "Apple",
                                                                  familyName: "User"))

        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.session.refreshToken == signedInSession.session.refreshToken)
        #expect(session.user.id == signedInSession.user.id)
        #expect(session.user.email == signedInSession.user.email)
        #expect(session.user.name == signedInSession.user.name)
        #expect(secondsBetween(session.session.expiresAt, signedInSession.session.expiresAt) <= 1)

        let persisted = try store.loadSession(for: "test-key")
        #expect(persisted?.session.id == signedInSession.session.id)
        #expect(persisted?.session.accessToken == signedInSession.session.accessToken)
        #expect(persisted?.session.refreshToken == signedInSession.session.refreshToken)
        #expect(persisted?.user.id == signedInSession.user.id)
        #expect(persisted?.user.email == signedInSession.user.email)
        #expect(persisted?.user.name == signedInSession.user.name)
        #expect(secondsBetween(persisted?.session.expiresAt, signedInSession.session.expiresAt) <= 1)
    }
}

private struct MockTransport: BetterAuthTransport {
    let handler: @Sendable (URLRequest) async throws -> (Data, URLResponse)

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await handler(request)
    }
}

private actor SequencedMockTransport: BetterAuthTransport {
    enum Entry {
        case raw(Data, Int)
        case handler((URLRequest) throws -> (Data, URLResponse))

        static func response(statusCode: Int, jsonObject: Any) -> Entry {
            .raw(try! JSONSerialization.data(withJSONObject: jsonObject), statusCode)
        }

        static func response(statusCode: Int, encodable: some Encodable) -> Entry {
            .raw(try! encodeJSON(encodable), statusCode)
        }
    }

    private var entries: [Entry]

    init(_ entries: [Entry]) {
        self.entries = entries
    }

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard !entries.isEmpty else {
            fatalError("No mock responses left")
        }

        let entry = entries.removeFirst()
        switch entry {
        case let .raw(data, statusCode):
            return response(for: request, statusCode: statusCode, data: data)

        case let .handler(handler):
            return try handler(request)
        }
    }
}

private struct SignOutResult: Encodable {
    let success: Bool
}

private struct ProtectedResponse: Codable, Equatable {
    let email: String
    let username: String?

    init(email: String, username: String? = nil) {
        self.email = email
        self.username = username
    }
}

private func emptyResponse(for request: URLRequest) -> (Data, URLResponse) {
    response(for: request, statusCode: 200, data: Data())
}

private func encodeJSON(_ value: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

private func response(for request: URLRequest, statusCode: Int, data: Data) -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: request.url ?? URL(string: "https://example.com")!,
                                   statusCode: statusCode,
                                   httpVersion: nil,
                                   headerFields: nil)!
    return (data, response)
}

private func secondsBetween(_ lhs: Date?, _ rhs: Date?) -> TimeInterval {
    guard let lhs, let rhs else { return .infinity }
    return abs(lhs.timeIntervalSince1970 - rhs.timeIntervalSince1970)
}

private func assertRequestFailed(statusCode expectedStatusCode: Int,
                                 message expectedMessage: String?,
                                 fileID: String = #fileID,
                                 filePath: String = #filePath,
                                 line: Int = #line,
                                 column: Int = #column,
                                 operation: () async throws -> some Any) async
{
    let sourceLocation = SourceLocation(fileID: fileID, filePath: filePath, line: line, column: column)
    do {
        _ = try await operation()
        Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: sourceLocation)
    } catch let BetterAuthError.requestFailed(statusCode, message, _, _) {
        #expect(statusCode == expectedStatusCode, sourceLocation: sourceLocation)
        #expect(message == expectedMessage, sourceLocation: sourceLocation)
    } catch {
        Issue.record("Expected BetterAuthError.requestFailed but got \(error)", sourceLocation: sourceLocation)
    }
}

private func assertRequestFailedJSON(statusCode expectedStatusCode: Int,
                                     expectedJSON: [String: String],
                                     fileID: String = #fileID,
                                     filePath: String = #filePath,
                                     line: Int = #line,
                                     column: Int = #column,
                                     operation: () async throws -> some Any) async
{
    let sourceLocation = SourceLocation(fileID: fileID, filePath: filePath, line: line, column: column)
    do {
        _ = try await operation()
        Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: sourceLocation)
    } catch let BetterAuthError.requestFailed(statusCode, message, _, response) {
        #expect(statusCode == expectedStatusCode, sourceLocation: sourceLocation)
        if let expectedMessage = expectedJSON["message"] {
            #expect(message == expectedMessage || response?.message == expectedMessage, sourceLocation: sourceLocation)
        }
        if let expectedCode = expectedJSON["code"] {
            #expect(response?.code == expectedCode, sourceLocation: sourceLocation)
        }
    } catch {
        Issue.record("Expected BetterAuthError.requestFailed but got \(error)", sourceLocation: sourceLocation)
    }
}
