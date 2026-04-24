import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct SocialAndUsernameAuthTests {
    @Test
    func typedAuthProviderIDsPreserveWireValues() throws {
        let social = SocialSignInRequest(provider: .google,
                                         callbackURL: "betterauth://callback",
                                         scopes: ["email", "profile"])
        #expect(social.provider == "google")

        let genericOAuth = GenericOAuthSignInRequest(provider: .github,
                                                     callbackURL: "betterauth://oauth/callback")
        #expect(genericOAuth.providerId == "github")

        let custom: AuthProviderID = "enterprise-sso"
        let link = LinkSocialAccountRequest(provider: custom,
                                            idToken: SocialIDTokenPayload(token: "id-token"))
        #expect(link.provider == "enterprise-sso")

        let encoded = try JSONEncoder().encode(AuthProviderID.microsoft)
        let decoded = try JSONDecoder().decode(AuthProviderID.self, from: encoded)
        #expect(decoded == .microsoft)
    }

    @Test
    func linkSocialAccountDecodesSuccessResponse() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/link-social")
                                 try expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let payload = try JSONDecoder().decode(LinkSocialAccountRequest.self,
                                                                        from: try #require(request.httpBody))
                                 try expect(payload.provider == "google")
                                 try expect(payload.idToken?.token == "valid-google-token")
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
            try expect(request.url?.path == "/api/auth/forget-password")
            try expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(ForgotPasswordRequest.self, from: try #require(request.httpBody))
            try expect(payload.email == "reset@example.com")
            try expect(payload.redirectTo == "https://app.example.com/reset")

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
            try expect(request.url?.path == "/api/auth/reset-password")
            try expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(ResetPasswordRequest.self, from: try #require(request.httpBody))
            try expect(payload.token == "reset-token")
            try expect(payload.newPassword == "new-password-123")

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
            try expect(request.url?.path == "/api/auth/send-verification-email")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(SendVerificationEmailRequest.self,
                                                   from: try #require(request.httpBody))
            try expect(payload.email == nil)
            try expect(payload.callbackURL == "https://app.example.com/verify")

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
            try expect(request.url?.path == "/api/auth/verify-email")
            try expect(request.httpMethod == "GET")
            try expect(request.httpBody == nil)
            try expect(request.url?.query == "token=verify-token")
            let body = Data("""
            {"status":true,"session":null}
            """.utf8)
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
            try expect(request.url?.path == "/api/auth/verify-email")
            try expect(request.httpMethod == "GET")
            try expect(request.httpBody == nil)
            try expect(request.url?.query == "token=verify-token")
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
            try expect(request.url?.path == "/api/auth/change-email")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(ChangeEmailRequest.self, from: try #require(request.httpBody))
            try expect(payload.newEmail == "next@example.com")
            try expect(payload.callbackURL == "https://app.example.com/settings")

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
                try expect(request.url?.path == "/api/auth/change-password")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                let payload = try JSONDecoder().decode(ChangePasswordRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.revokeOtherSessions == true)

                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(ChangePasswordResponse(token: "rotated-token",
                                                                            user: .init(id: "user-1",
                                                                                        email: "user@example.com",
                                                                                        name: "Updated Name"))))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/get-session")
                try expect(request.httpMethod == "GET")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer rotated-token")
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
}
