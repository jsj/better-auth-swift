import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct SessionRestoreAndAuthStoreTests {
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
                                                   try expect(request.url?
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
                                                   try expect(request.url?.path == "/api/auth/magic-link/verify")
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
                                                   try expect(request.url?.path == "/api/auth/email-otp/verify-email")
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
}
