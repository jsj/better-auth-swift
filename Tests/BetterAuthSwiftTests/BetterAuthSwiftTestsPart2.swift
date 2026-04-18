import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct BetterAuthSwiftTestsPart2 {
    @Test
    func retryPolicyDelayAppliesBoundedJitter() {
        let policy = RetryPolicy(maxRetries: 3, baseDelay: 2, maxDelay: 10, jitterFactor: 0.25)
        let delay = policy.delay(for: 2)

        #expect(delay >= 3)
        #expect(delay <= 4)
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

        #expect(endpoints.session.currentSessionPath == "/api/auth/get-session")
        #expect(endpoints.session.sessionRefreshPath == "/api/auth/get-session")
        #expect(endpoints.session.signOutPath == "/api/auth/sign-out")
        #expect(endpoints.auth.forgotPasswordPath == "/api/auth/forget-password")
        #expect(endpoints.auth.resetPasswordPath == "/api/auth/reset-password")
        #expect(endpoints.user.sendVerificationEmailPath == "/api/auth/send-verification-email")
        #expect(endpoints.user.verifyEmailPath == "/api/auth/verify-email")
        #expect(endpoints.user.changeEmailPath == "/api/auth/change-email")
        #expect(endpoints.user.updateUserPath == "/api/auth/update-user")
        #expect(endpoints.user.changePasswordPath == "/api/auth/change-password")
        #expect(endpoints.auth.socialSignInPath == "/api/auth/sign-in/social")
        #expect(endpoints.oauth.listLinkedAccountsPath == "/api/auth/list-accounts")
        #expect(endpoints.oauth.linkSocialAccountPath == "/api/auth/link-social")
        #expect(endpoints.passkey.registerOptionsPath == "/api/auth/passkey/generate-register-options")
        #expect(endpoints.passkey.authenticateOptionsPath == "/api/auth/passkey/generate-authenticate-options")
        #expect(endpoints.passkey.registerPath == "/api/auth/passkey/verify-registration")
        #expect(endpoints.passkey.authenticatePath == "/api/auth/passkey/verify-authentication")
        #expect(endpoints.passkey.listPath == "/api/auth/passkey/list-user-passkeys")
        #expect(endpoints.passkey.updatePath == "/api/auth/passkey/update-passkey")
        #expect(endpoints.passkey.deletePath == "/api/auth/passkey/delete-passkey")
        #expect(endpoints.twoFactor.enablePath == "/api/auth/two-factor/enable")
        #expect(endpoints.twoFactor.verifyTOTPPath == "/api/auth/two-factor/verify-totp")
        #expect(endpoints.twoFactor.sendOTPPath == "/api/auth/two-factor/send-otp")
        #expect(endpoints.twoFactor.verifyOTPPath == "/api/auth/two-factor/verify-otp")
        #expect(endpoints.twoFactor.verifyBackupCodePath == "/api/auth/two-factor/verify-backup-code")
        #expect(endpoints.twoFactor.generateBackupCodesPath == "/api/auth/two-factor/generate-backup-codes")
        #expect(endpoints.twoFactor.disablePath == "/api/auth/two-factor/disable")
        #expect(endpoints.session.listSessionsPath == "/api/auth/list-sessions")
        #expect(endpoints.session.listDeviceSessionsPath == "/api/auth/multi-session/list-device-sessions")
        #expect(endpoints.session.setActiveDeviceSessionPath == "/api/auth/multi-session/set-active")
        #expect(endpoints.session.revokeDeviceSessionPath == "/api/auth/multi-session/revoke")
        #expect(endpoints.session.sessionJWTPath == "/api/auth/token")
        #expect(endpoints.session.jwksPath == "/api/auth/jwks")
        #expect(endpoints.session.revokeSessionPath == "/api/auth/revoke-session")
        #expect(endpoints.session.revokeSessionsPath == "/api/auth/revoke-sessions")
        #expect(endpoints.session.revokeOtherSessionsPath == "/api/auth/revoke-other-sessions")
        #expect(endpoints.user.deleteUserPath == "/api/auth/delete-user")
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

    // MARK: - 2FA Disable

    @Test
    func disableTwoFactorUsesConfiguredEndpointAndPassword() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
            #expect(request.url?.path == "/api/auth/two-factor/disable")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
            let payload = try JSONDecoder().decode(TwoFactorDisableRequest.self, from: try #require(request.httpBody))
            #expect(payload.password == "my-password")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let result = try await client.auth.disableTwoFactor(TwoFactorDisableRequest(password: "my-password"))
        #expect(result == true)
        #expect(await client.auth.currentSession() != nil)
    }

    @Test
    func disableTwoFactorPreservesFailureSemantics() async throws {
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
            _ = try await client.auth.disableTwoFactor(TwoFactorDisableRequest(password: "wrong"))
            Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: location)
        } catch let BetterAuthError.requestFailed(statusCode, _, _, response) {
            #expect(statusCode == 401, sourceLocation: location)
            #expect(response?.code == "INVALID_PASSWORD", sourceLocation: location)
        }
    }

    @Test
    func enableThenDisableTwoFactorRoundTrip() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([// Enable 2FA
            .handler { request in
                #expect(request.url?.path == "/api/auth/two-factor/enable")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(TwoFactorEnableResponse(totpURI: "otpauth://totp/Example:user@example.com?secret=ABC",
                                                                             backupCodes: ["code-1", "code-2"])))
            },
            // Disable 2FA
            .handler { request in
                #expect(request.url?.path == "/api/auth/two-factor/disable")
                return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
            }])

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.applyRestoredSession(session)

        let enableResult = try await client.auth.enableTwoFactor(TwoFactorEnableRequest(password: "password"))
        #expect(enableResult.totpURI.contains("otpauth://"))
        #expect(enableResult.backupCodes.count == 2)

        let disableResult = try await client.auth.disableTwoFactor(TwoFactorDisableRequest(password: "password"))
        #expect(disableResult == true)
        #expect(await client.auth.currentSession() != nil)
    }

    // MARK: - Session Revocation Edge Cases

    @Test
    func revokeSessionPreservesCurrentSessionWhenRevokingDifferentToken() async throws {
        let session =
            BetterAuthSession(session: .init(id: "session-current", userId: "user-1", accessToken: "current-token"),
                              user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
            #expect(request.url?.path == "/api/auth/revoke-session")
            let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            #expect(body?["token"] as? String == "other-device-token")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(session)
        try store.saveSession(session, for: "test-key")

        let result = try await client.auth.revokeSession(token: "other-device-token")
        #expect(result == true)
        #expect(await client.auth.currentSession()?.session.accessToken == "current-token")
        #expect(try store.loadSession(for: "test-key")?.session.accessToken == "current-token")
    }

    @Test
    func revokeSessionsClearsLocalStateAndSignsOut() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
            #expect(request.url?.path == "/api/auth/revoke-sessions")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)
        try await client.auth.applyRestoredSession(session)
        try store.saveSession(session, for: "test-key")

        let result = try await client.auth.revokeSessions()
        #expect(result == true)
        #expect(await client.auth.currentSession() == nil)
        #expect(try store.loadSession(for: "test-key") == nil)
    }

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
            #expect(request.url?.path == "/api/auth/delete-user")
            #expect(request.httpMethod == "POST")
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
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
            #expect(request.url?.path == "/api/auth/delete-user")
            let payload = try JSONDecoder().decode(DeleteUserRequest.self, from: try #require(request.httpBody))
            #expect(payload.token == "password-confirmation-token")
            #expect(payload.callbackURL == "https://example.com/deleted")
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
            #expect(request.url?.path == "/api/auth/email/sign-up")
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
            #expect(request.url?.path == "/api/auth/apple/native")
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
                #expect(request.url?.path == "/api/auth/email/sign-in")
                #expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(EmailSignInRequest.self, from: try #require(request.httpBody))
                #expect(payload.email == "user@example.com")
                #expect(payload.password == "correct-password")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthSession(session: .init(id: "session-reauth",
                                                                                      userId: "user-1",
                                                                                      accessToken: "reauth-token"),
                                                                       user: .init(id: "user-1",
                                                                                   email: "user@example.com"))))
            },
            // Revoke ephemeral verification session
            .handler { request in
                #expect(request.url?.path == "/api/auth/revoke-session")
                return response(for: request, statusCode: 200, data: Data())
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
    func genericOAuthCompletionUsesConfiguredCallbackTemplate() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    endpoints: .init(genericOAuthCallbackPath: "/api/auth/custom-oauth/{providerId}/complete")),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 #expect(request.url?.path == "/api/auth/custom-oauth/fixture-generic/complete")
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
}
