import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct PasskeyLifecycleTests {
    // MARK: - Passkey Error Edge Cases

    @Test
    func deletePasskeyPreservesNotFoundFailure() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.response(statusCode: 404,
                                                          jsonObject: ["code": "PASSKEY_NOT_FOUND",
                                                                       "message": "Passkey not found"])])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let location = SourceLocation(fileID: #fileID, filePath: #filePath, line: #line + 1, column: #column)
        do {
            _ = try await client.auth.deletePasskey(DeletePasskeyRequest(id: "nonexistent"))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 404, sourceLocation: location)
            #expect(response?.code == "PASSKEY_NOT_FOUND", sourceLocation: location)
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
                                 try expect(request.url?
                                     .path == "/api/auth/passkey/generate-authenticate-options")
                                 try expect(request.httpMethod == "GET")
                                 try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
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
                try expect(request.url?.path == "/api/auth/passkey/generate-register-options")
                try expect(request.url?.query?.contains("name=MacBook") == true)
                try expect(request.url?.query?.contains("authenticatorAttachment=platform") == true)
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(options))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/passkey/verify-registration")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                let payload = try JSONDecoder().decode(PasskeyRegistrationRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.name == "MacBook")
                try expect(payload.response.id == "credential-id")
                return try response(for: request, statusCode: 200, data: encodeJSON(createdPasskey))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/passkey/list-user-passkeys")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer passkey-token")
                return try response(for: request, statusCode: 200, data: encodeJSON([createdPasskey]))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/passkey/update-passkey")
                let payload = try JSONDecoder().decode(UpdatePasskeyRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.id == "passkey-1")
                try expect(payload.name == "Renamed MacBook")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(UpdatePasskeyResponse(passkey: renamedPasskey)))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/passkey/delete-passkey")
                let payload = try JSONDecoder().decode(DeletePasskeyRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.id == "passkey-1")
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
                                                                      "message": "Challenge not found"],
                                      operation: {
                                          _ = try await client.auth
                                              .authenticateWithPasskey(.init(response: .init(id: "credential-id",
                                                                                             rawId: "credential-raw",
                                                                                             response: .init(clientDataJSON: "missing-challenge"))))
                                      })

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "AUTHENTICATION_FAILED",
                                                                      "message": "Authentication failed"],
                                      operation: {
                                          _ = try await client.auth
                                              .authenticateWithPasskey(.init(response: .init(id: "credential-id",
                                                                                             rawId: "credential-raw",
                                                                                             response: .init(clientDataJSON: "wrong-origin"))))
                                      })

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "FAILED_TO_VERIFY_REGISTRATION",
                                                                      "message": "Failed to verify registration"],
                                      operation: {
                                          _ = try await client.auth
                                              .registerPasskey(.init(response: .init(id: "credential-id",
                                                                                     rawId: "credential-raw",
                                                                                     response: .init(clientDataJSON: "stale-registration",
                                                                                                     attestationObject: "attestation"))))
                                      })
    }

    @Test
    func socialSignInReturnsAuthorizationURLWithoutPersistingSession() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/sign-in/social")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")
            let payload = try JSONDecoder().decode(SocialSignInRequest.self, from: try #require(request.httpBody))
            try expect(payload.provider == "google")
            try expect(payload.disableRedirect == true)

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
}
