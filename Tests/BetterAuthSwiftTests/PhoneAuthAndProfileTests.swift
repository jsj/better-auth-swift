import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct PhoneAuthAndProfileTests {
    @Test
    func phoneNumberVerifyUsesPublicRouteWhenNotUpdatingPhoneNumber() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/phone-number/verify")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            let payload = try JSONDecoder().decode(PhoneOTPVerifyRequest.self, from: try #require(request.httpBody))
            try expect(payload.phoneNumber == "+15555550123")
            try expect(payload.code == "123456")
            try expect(payload.updatePhoneNumber == nil)

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
                                                                      "message": "Invalid OTP"],
                                      operation: {
                                          _ = try await client.auth
                                              .signInWithPhoneOTP(.init(phoneNumber: "+15555550123",
                                                                        password: "password111"))
                                      })

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "OTP_EXPIRED",
                                                                      "message": "OTP expired"],
                                      operation: {
                                          _ = try await client.auth
                                              .signInWithPhoneOTP(.init(phoneNumber: "+15555550123",
                                                                        password: "password222"))
                                      })
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
                                                                    endpoints: .init(auth: .init(nativeAppleSignInPath: "/api/auth/apple/native")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/apple/native")
                                 try expect(request.httpMethod == "POST")
                                 try expect(request
                                     .value(forHTTPHeaderField: "Content-Type") == "application/json")
                                 try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
                                 try expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")

                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 try expect(payload.token == "identity-token")
                                 try expect(payload.nonce == "raw-nonce")
                                 try expect(payload.authorizationCode == "auth-code")
                                 try expect(payload.email == "apple@example.com")
                                 try expect(payload.givenName == "Apple")
                                 try expect(payload.familyName == "User")

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
                                                                    endpoints: .init(auth: .init(nativeAppleSignInPath: "/api/auth/apple/native")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/apple/native")
                                 try expect(request.value(forHTTPHeaderField: "Origin") == "app://snoozy")
                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 try expect(payload.token == "repeat-identity-token")
                                 try expect(payload.nonce == "repeat-raw-nonce")
                                 try expect(payload.email == nil)
                                 try expect(payload.givenName == nil)
                                 try expect(payload.familyName == nil)
                                 try expect(payload.authorizationCode == nil)
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
                                                                    endpoints: .init(auth: .init(nativeAppleSignInPath: "/api/auth/custom-apple/native",
                                                                                                 socialSignInPath: "/api/auth/sign-in/social")),
                                                                    requestOrigin: "app://snoozy"),
                             sessionStore: store,
                             transport: MockTransport { request in
                                 try expect(request.url?.path == "/api/auth/custom-apple/native")
                                 let payload = try JSONDecoder().decode(AppleNativeSignInPayload.self,
                                                                        from: try #require(request.httpBody))
                                 try expect(payload.token == "identity-token")
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
