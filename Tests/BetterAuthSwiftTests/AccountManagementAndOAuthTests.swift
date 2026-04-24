import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct AccountManagementAndOAuthTests {
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
    func anonymousSignInRejectsMismatchedMaterializedUser() async throws {
        let transport = SequencedMockTransport([.response(statusCode: 200, jsonObject: ["token": "anon-token",
                                                                                        "user": ["id": "anon-user",
                                                                                                 "email": "temp@anon.example.com",
                                                                                                 "name": "Anonymous"]]),
                                                .response(statusCode: 200,
                                                          jsonObject: ["session": ["id": "session-anon",
                                                                                   "userId": "different-user",
                                                                                   "accessToken": "anon-token",
                                                                                   "expiresAt": ISO8601DateFormatter()
                                                                                       .string(from: Date()
                                                                                           .addingTimeInterval(3600))],
                                                                       "user": ["id": "different-user",
                                                                                "email": "other@example.com",
                                                                                "name": "Other User"]])])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: store,
                             transport: transport)

        do {
            _ = try await client.auth.signInAnonymously()
            Issue.record("Expected anonymous sign-in to reject mismatched materialized user")
        } catch let error as BetterAuthError {
            guard case .invalidResponse = error else {
                Issue.record("Expected BetterAuthError.invalidResponse but got \(error)")
                return
            }
        }

        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "better-auth.session") == nil)
    }

    // MARK: - Delete User

    @Test
    func deleteUserClearsSessionAndHitsConfiguredEndpoint() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))
        let store = InMemorySessionStore()
        try store.saveSession(session, for: "test-key")

        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/delete-user")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let result = try await client.auth.deleteUser()
        #expect(result == true)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

    @Test
    func deleteUserWithPasswordTokenSendsToken() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/delete-user")
            let payload = try JSONDecoder().decode(DeleteUserRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.token == "password-confirmation-token")
            try expect(payload.callbackURL == "https://example.com/deleted")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let result = try await client.auth.deleteUser(DeleteUserRequest(callbackURL: "https://example.com/deleted",
                                                                        token: "password-confirmation-token"))
        #expect(result == true)
    }

    @Test
    func deleteUserPreservesFailureSemantics() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 403,
                                                          jsonObject: ["code": "FORBIDDEN",
                                                                       "message": "Password required"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.deleteUser()
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 403, sourceLocation: location)
            #expect(response?.code == "FORBIDDEN", sourceLocation: location)
        }
        #expect(await client.auth.currentSession() != nil)
    }

    // MARK: - Anonymous Upgrade

    @Test
    func upgradeAnonymousWithEmailRequiresExistingSession() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in emptyResponse(for: request) })

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.upgradeAnonymousWithEmail(EmailSignUpRequest(email: "user@example.com",
                                                                                   password: "password123",
                                                                                   name: "Test"))
            Issue.record("Expected BetterAuthError.missingSession", sourceLocation: location)
        } catch BetterAuthError.missingSession {
            // expected
        }
    }

    @Test
    func upgradeAnonymousWithEmailPersistsUpgradedSession() async throws {
        let upgradedSession = BetterAuthSession(session: .init(id: "session-upgraded",
                                                               userId: "user-upgraded",
                                                               accessToken: "upgraded-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-upgraded", email: "real@example.com",
                                                            name: "Real User"))
        let anonSession =
            BetterAuthSession(session: .init(id: "session-anon", userId: "anon-user", accessToken: "anon-token"),
                              user: .init(id: "anon-user", email: "temp@anon.example.com"))

        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/email/sign-up")
            return try response(for: request, statusCode: 200, data: encodeJSON(upgradedSession))
        }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(anonSession)

        let result = try await client.auth.upgradeAnonymousWithEmail(EmailSignUpRequest(email: "real@example.com",
                                                                                        password: "password123",
                                                                                        name: "Real User"))
        if case let .signedIn(session) = result {
            #expect(session.user.email == "real@example.com")
            #expect(session.session.accessToken == "upgraded-token")
        } else {
            Issue.record("Expected signed-in upgrade result")
        }

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.user.email == "real@example.com")
    }

    @Test
    func upgradeAnonymousWithApplePersistsUpgradedSession() async throws {
        let upgradedSession = BetterAuthSession(session: .init(id: "session-apple",
                                                               userId: "apple-user",
                                                               accessToken: "apple-token"),
                                                user: .init(id: "apple-user", email: "apple@example.com",
                                                            name: "Apple User"))
        let anonSession =
            BetterAuthSession(session: .init(id: "session-anon", userId: "anon-user", accessToken: "anon-token"),
                              user: .init(id: "anon-user"))

        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/apple/native")
            return try response(for: request, statusCode: 200, data: encodeJSON(upgradedSession))
        }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(anonSession)

        let session = try await client.auth.upgradeAnonymousWithApple(AppleNativeSignInPayload(token: "apple-id-token",
                                                                                               nonce: "nonce"))
        #expect(session.user.email == "apple@example.com")
        #expect(session.session.accessToken == "apple-token")
        #expect(try store.loadSession(for: "test-key")?.user.email == "apple@example.com")
    }

    // MARK: - Re-authentication

    @Test
    func reauthenticateSucceedsWithValidPassword() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
                try expect(request.url?.path == "/api/auth/email/sign-in")
                try expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(EmailSignInRequest.self,
                                                       from: try requireValue(request.httpBody))
                try expect(payload.email == "user@example.com")
                try expect(payload.password == "correct-password")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthSession(session: .init(id: "session-reauth",
                                                                                      userId: "user-1",
                                                                                      accessToken: "reauth-token"),
                                                                       user: .init(id: "user-1",
                                                                                   email: "user@example.com"))))
            },
            // Revoke ephemeral verification session
            .handler { request in
                try expect(request.url?.path == "/api/auth/revoke-session")
                let payload = try requireValue(JSONSerialization
                    .jsonObject(with: try requireValue(request.httpBody)) as? [String: String])
                try expect(payload["token"] == "reauth-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let result = try await client.auth.reauthenticate(password: "correct-password")
        #expect(result == true)
    }

    @Test
    func reauthenticateDoesNotReplaceCurrentSession() async throws {
        let originalSession =
            BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "original-token"),
                              user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthSession(session: .init(id: "session-reauth",
                                                                                                      userId: "user-1",
                                                                                                      accessToken: "reauth-token"),
                                                                                       user: .init(id: "user-1",
                                                                                                   email: "user@example.com"))),
                                                // Revoke ephemeral verification session
                                                .response(statusCode: 200, jsonObject: ["status": true])])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(originalSession)

        _ = try await client.auth.reauthenticate(password: "correct-password")

        let current = await client.auth.currentSession()
        #expect(current?.session.accessToken == "original-token")
    }

    @Test
    func reauthenticateFailsClosedWhenTemporarySessionRevokeFails() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: BetterAuthSession(session: .init(id: "session-reauth",
                                                                                                      userId: "user-1",
                                                                                                      accessToken: "reauth-token"),
                                                                                       user: .init(id: "user-1",
                                                                                                   email: "user@example.com"))),
                                                .response(statusCode: 500,
                                                          jsonObject: ["code": "INTERNAL_SERVER_ERROR",
                                                                       "message": "revoke failed"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    retryPolicy: RetryPolicy.none),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        do {
            _ = try await client.auth.reauthenticate(password: "correct-password")
            Issue.record("Expected revoke failure to fail closed")
        } catch let BetterAuthError.requestFailed(statusCode, _, _, _) {
            #expect(statusCode == 500)
        }
    }

    @Test
    func reauthenticateFailsWithInvalidPassword() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 401,
                                                          jsonObject: ["code": "INVALID_PASSWORD",
                                                                       "message": "Invalid password"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.reauthenticate(password: "wrong-password")
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, _) {
            #expect(statusCode == 401, sourceLocation: location)
        }
    }

    @Test
    func genericOAuthInitiationAndCompletionMaterializeNativeSession() async throws {
        let store = InMemorySessionStore()
        let transport = MockTransport { request in
            if request.url?.path == "/api/auth/sign-in/oauth2" {
                try expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(GenericOAuthSignInRequest.self,
                                                       from: try requireValue(request.httpBody))
                try expect(payload.providerId == "fixture-generic")
                try expect(payload.disableRedirect == true)
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(GenericOAuthAuthorizationResponse(url: "https://fixture-oauth.example.com/oauth/authorize?state=fixture-state",
                                                                                       redirect: false)))
            }

            if request.url?.path == "/api/auth/oauth2/callback/fixture-generic" {
                try expect(request.httpMethod == "GET")
                let components = URLComponents(url: try requireValue(request.url), resolvingAgainstBaseURL: true)
                try expect(components?.queryItems?.first(where: { $0.name == "code" })?.value == "fixture-code")
                try expect(components?.queryItems?.first(where: { $0.name == "state" })?.value == "fixture-state")
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
    func genericOAuthCompletionUsesConfiguredCallbackTemplate() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    endpoints: .init(genericOAuthCallbackPath: "/api/auth/custom-oauth/{providerId}/complete")),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/custom-oauth/fixture-generic/complete")
                                 return try response(for: request,
                                                     statusCode: 200,
                                                     data: encodeJSON(BetterAuthSession(session: .init(id: "session-oauth",
                                                                                                       userId: "oauth-user",
                                                                                                       accessToken: "oauth-token"),
                                                                                        user: .init(id: "oauth-user",
                                                                                                    email: "oauth@example.com"))))
                             })

        let session = try await client.auth
            .completeGenericOAuth(GenericOAuthCallbackRequest(providerId: "fixture-generic",
                                                              code: "fixture-code",
                                                              state: "fixture-state"))

        #expect(session.session.accessToken == "oauth-token")
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
                                 try expect(request.url?.path == "/api/auth/list-accounts")
                                 try expect(request
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
                                 try expect(request.url?.path == "/api/auth/oauth2/link")
                                 try expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let payload = try JSONDecoder().decode(GenericOAuthSignInRequest.self,
                                                                        from: try requireValue(request.httpBody))
                                 try expect(payload.providerId == "fixture-generic")
                                 try expect(payload.callbackURL == "betterauth://oauth/success")
                                 try expect(payload.disableRedirect == true)
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
                                 try expect(request.url?.path == "/api/auth/oauth2/callback/fixture-generic")
                                 try expect(request.httpMethod == "GET")
                                 try expect(request
                                     .value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                                 let components = URLComponents(url: try requireValue(request.url),
                                                                resolvingAgainstBaseURL: true)
                                 try expect(components?.queryItems?.first(where: { $0.name == "code" })?
                                     .value == "fixture-code")
                                 try expect(components?.queryItems?.first(where: { $0.name == "state" })?
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
}
