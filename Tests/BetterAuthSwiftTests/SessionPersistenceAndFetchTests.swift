import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct SessionPersistenceAndFetchTests {
    @Test
    func fetchCurrentSessionDecodesISO8601Expiry() async throws {
        let expiry = "2026-03-29T16:00:00Z"
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         try expect(request.url?.path == "/api/auth/get-session")
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
                                         try expect(request.url?.path == "/api/auth/get-session")
                                         try expect(request
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
                                         try expect(request.url?.path == "/api/auth/get-session")
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
                                         try expect(request.url?.path == "/api/auth/get-session")
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
                                 try expect(request.url?.path == "/api/auth/email/sign-in")
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
    func updateSessionPublishesLifecycleEvents() async throws {
        let emitter = AuthEventEmitter()
        let initial = BetterAuthSession(session: .init(id: "session-1",
                                                       userId: "user-1",
                                                       accessToken: "token-1",
                                                       refreshToken: "refresh-1",
                                                       expiresAt: Date().addingTimeInterval(300)),
                                        user: .init(id: "user-1", email: "test@example.com"))
        let refreshed = BetterAuthSession(session: .init(id: "session-1",
                                                         userId: "user-1",
                                                         accessToken: "token-2",
                                                         refreshToken: "refresh-2",
                                                         expiresAt: Date().addingTimeInterval(3600)),
                                          user: .init(id: "user-1", email: "test@example.com"))
        let manager =
            BetterAuthSessionManager(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                            storage: .init(key: "test-key")),
                                     sessionStore: InMemorySessionStore(),
                                     transport: MockTransport { request in
                                         emptyResponse(for: request)
                                     },
                                     eventEmitter: emitter)

        var iterator = emitter.stateChanges.makeAsyncIterator()

        try await manager.updateSession(initial)
        let signedIn = await iterator.next()
        #expect(signedIn?.event == .signedIn)
        #expect(signedIn?.session == initial)

        try await manager.updateSession(refreshed)
        let tokenRefreshed = await iterator.next()
        #expect(tokenRefreshed?.event == .tokenRefreshed)
        #expect(tokenRefreshed?.session == refreshed)
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
                                 try expect(request.url?.path == "/api/auth/email/sign-in")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(signedIn))
                             },
                             eventEmitter: emitter)

        let recorder = Locked<AuthStateChange?>(nil)
        let registration = emitter.on { change in
            recorder.withLock { $0 = change }
        }
        defer { registration.remove() }

        try await client.auth.signInWithEmail(.init(email: "test@example.com", password: "password123"))
        try await waitForCondition { recorder.withLock { $0 } != nil }
        let observed = recorder.withLock { $0 }
        #expect(observed?.event == .signedIn)
        #expect(observed?.session == signedIn)
        #expect(observed?.transition?.phase == .authenticated)
    }

    @Test @MainActor
    func authStoreTracksExternalAuthStateChanges() async throws {
        let signedIn = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token"),
                                         user: .init(id: "user-1", email: "test@example.com"))
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/email/sign-in")
                                 return try response(for: request, statusCode: 200, data: encodeJSON(signedIn))
                             })
        let store = AuthStore(client: client)

        _ = store
        try await client.auth.signInWithEmail(.init(email: "test@example.com", password: "password123"))
        await waitUntil { store.session == signedIn }
        #expect(store.session == signedIn)
        #expect(store.launchState == .authenticated(signedIn))

        try await client.auth.signOut(remotely: false)
        await waitUntil { store.session == nil && store.launchState == .unauthenticated }
        #expect(store.session == nil)
        #expect(store.launchState == .unauthenticated)
    }

    @Test @MainActor
    func authStoreExposesStructuredErrorForBetterAuthFailures() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/email/sign-in")
                                 return response(for: request,
                                                 statusCode: 401,
                                                 data: Data(#"{"message":"nope","code":"INVALID_CREDENTIALS"}"#.utf8))
                             })
        let store = AuthStore(client: client)

        await store.signInWithEmail(.init(email: "test@example.com", password: "wrong"))

        let error = try #require(store.lastError)
        #expect(error.statusCode == 401)
        #expect(error.authErrorCode == .invalidCredentials)
        #expect(store.statusMessage == "Invalid credentials.")
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
