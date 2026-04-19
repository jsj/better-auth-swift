import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct EmailPasswordAuthTests {
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
                try expect(request.url?.path == "/api/auth/is-username-available")
                try expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(UsernameAvailabilityRequest.self,
                                                       from: try requireValue(request.httpBody))
                try expect(payload.username == "PRIORITY_USER")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(UsernameAvailabilityResponse(available: false)))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/is-username-available")
                let payload = try JSONDecoder().decode(UsernameAvailabilityRequest.self,
                                                       from: try requireValue(request.httpBody))
                try expect(payload.username == "fresh_user")
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
            try expect(request.url?.path == "/api/auth/email/sign-up")
            let payload = try JSONDecoder().decode(EmailSignUpRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.username == "Custom_User")
            try expect(payload.displayUsername == nil)
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
            try expect(request.url?.path == "/api/auth/update-user")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
            let payload = try JSONDecoder().decode(UpdateUserRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.username == "Priority_User")
            try expect(payload.displayUsername == "Priority Display Name")
            try expect(payload.name == "Updated Name")

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
            try expect(request.url?.path == "/api/auth/sign-in/magic-link")
            try expect(request.httpMethod == "POST")
            let payload = try JSONSerialization.jsonObject(with: try requireValue(request.httpBody)) as? [String: Any]
            try expect(payload?["email"] as? String == "magic@example.com")
            try expect(payload?["name"] as? String == "Magic User")
            try expect(payload?["callbackURL"] as? String == "betterauth://magic/success")
            try expect(payload?["newUserCallbackURL"] as? String == "betterauth://magic/new")
            try expect(payload?["errorCallbackURL"] as? String == "betterauth://magic/error")
            let metadata = payload?["metadata"] as? [String: String]
            try expect(metadata?["source"] == "ios")
            try expect(metadata?["campaign"] == "spring")

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
}
