import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct BetterAuthSwiftTestsPart3 {
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
                                data: encodeJSON(PhoneOTPRequestResponse(message: "otp queued", success: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let success = try await client.auth.requestPhoneOTP(PhoneOTPRequest(phoneNumber: "+15555550123"))
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
    func requestPhoneOTPThrowsWhenResponseOmitsSuccessAndStatus() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try response(for: request,
                                              statusCode: 200,
                                              data: encodeJSON(PhoneOTPRequestResponse(message: "ambiguous")))
                             })

        do {
            _ = try await client.auth.requestPhoneOTP(PhoneOTPRequest(phoneNumber: "+15555550123"))
            Issue.record("Expected BetterAuthError.invalidResponse")
        } catch let error as BetterAuthError {
            #expect(error.localizedDescription == BetterAuthError.invalidResponse.localizedDescription)
        }
    }


    @Test
    func requestClientAppliesConfiguredTimeoutToAuthenticatedRequests() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            return emptyResponse(for: request)
        }
        let configuration = BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                    networking: .init(timeoutInterval: 7))
        let client = BetterAuthClient(configuration: configuration,
                                      sessionStore: InMemorySessionStore(),
                                      transport: transport)
        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "current-token", expiresAt: Date().addingTimeInterval(3600)),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        _ = try await client.requests.send(path: "/protected", retryOnUnauthorized: false)
        let captured = try #require(requests.withLock { $0.first })
        #expect(captured.timeoutInterval == 7)
        #expect(captured.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
    }

}
