import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct BetterAuthSwiftTestsPart1 {
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

    @Test
    func genericOAuthCallbackPathUsesConfiguredTemplate() async throws {
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            endpoints: .init(genericOAuthCallbackPath: "/api/auth/custom-oauth/{providerId}/complete")),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         Issue.record("Transport should not be used while parsing incoming URL")
                                         return emptyResponse(for: request)
                                     })

        let oauthURL =
            try #require(URL(string: "betterauth://host/api/auth/custom-oauth/fixture-generic/complete?code=fixture-code&state=fixture-state"))

        #expect(await manager.parseIncomingURL(oauthURL)
            == .genericOAuth(.init(providerId: "fixture-generic", code: "fixture-code", state: "fixture-state")))
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
    func authStoreBootstrapSurfacesRecoverableFailureForDeferredRefresh() async throws {
        let stored = BetterAuthSession(session: .init(id: "session-1",
                                                      userId: "user-1",
                                                      accessToken: "token",
                                                      refreshToken: "refresh-token",
                                                      expiresAt: Date().addingTimeInterval(5)),
                                       user: .init(id: "user-1", email: "test@example.com"))

        let store = InMemorySessionStore()
        try store.saveSession(stored, for: "test-key")

        let authStore =
            AuthStore(client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                                      storage: .init(key: "test-key"),
                                                                                      clockSkew: 60),
                                               sessionStore: store,
                                               transport: MockTransport { _ in
                                                   throw URLError(.networkConnectionLost)
                                               }))

        await authStore.bootstrap()
        #expect(authStore.session == stored)
        #expect(authStore.lastRestoreResult == .restored(stored, source: .keychain, refresh: .deferred))
        #expect(authStore.launchState == .recoverableFailure(stored))
        #expect(authStore.statusMessage == "Session restored; refresh deferred")
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
    func authStateChangesStreamReplaysLatestSessionToNewSubscribers() async throws {
        let emitter = AuthEventEmitter()
        let signedIn = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                         user: .init(id: "user-1", email: "test@example.com"))
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/email/sign-in")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(signedIn))
                             },
                             eventEmitter: emitter)

        try await client.auth.signInWithEmail(.init(email: "test@example.com", password: "password123"))
        var iterator = client.authStateChanges.makeAsyncIterator()
        let stateChange = await iterator.next()

        #expect(stateChange?.event == .signedIn)
        #expect(stateChange?.session == signedIn)
        #expect(stateChange?.transition?.phase == .authenticated)
        #expect(client.onAuthStateChange.latest == stateChange)
    }

    @Test
    func authStateListenerReceivesStructuredTransition() async throws {
        let emitter = AuthEventEmitter()
        let signedIn = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                         user: .init(id: "user-1", email: "test@example.com"))
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/email/sign-in")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(signedIn))
                             },
                             eventEmitter: emitter)

        let recorder = Locked<AuthStateChange?>(nil)
        let registration = emitter.on { change in
            recorder.withLock { $0 = change }
        }
        defer { registration.remove() }

        try await client.auth.signInWithEmail(.init(email: "test@example.com", password: "password123"))
        let observed = recorder.withLock { $0 }
        #expect(observed?.event == .signedIn)
        #expect(observed?.session == signedIn)
        #expect(observed?.transition?.phase == .authenticated)
    }

    @Test
    func emptyModuleRegistryReportsNoModules() {
        let registry = BetterAuthModuleRegistry()

        #expect(registry.isEmpty == true)
        #expect(registry.registeredModuleIdentifiers.isEmpty)
        #expect(registry.runtime(for: "missing") == nil)
    }

    @Test @MainActor
    func authStoreTracksExternalAuthStateChanges() async throws {
        let signedIn = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                         user: .init(id: "user-1", email: "test@example.com"))
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/email/sign-in")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(signedIn))
                             })
        let store = AuthStore(client: client)

        _ = store
        await Task.yield()
        try await client.auth.signInWithEmail(.init(email: "test@example.com", password: "password123"))
        await waitUntil { store.session == signedIn }
        #expect(store.session == signedIn)
        #expect(store.launchState == .authenticated(signedIn))

        try await client.auth.signOut(remotely: false)
        await waitUntil { store.session == nil && store.launchState == .unauthenticated }
        #expect(store.session == nil)
        #expect(store.launchState == .unauthenticated)
    }

    @Test
    func configurationSupportsNestedAuthAndNetworkingOptions() throws {
        let configuration = BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                    auth: .init(clockSkew: 90, autoRefreshToken: false),
                                                    networking: .init(retryPolicy: .default,
                                                                      requestOrigin: "app://origin"))

        #expect(configuration.auth.clockSkew == 90)
        #expect(configuration.auth.autoRefreshToken == false)
        #expect(configuration.clockSkew == 90)
        #expect(configuration.networking.requestOrigin == "app://origin")
        #expect(configuration.requestOrigin == "app://origin")
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
}
