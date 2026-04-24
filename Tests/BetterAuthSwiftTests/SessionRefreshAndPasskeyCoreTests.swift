import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct SessionRefreshAndPasskeyCoreTests {
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
                                         try expect(request.url?.path == "/api/auth/get-session")
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
                                         try expect(request.url?.path == "/api/auth/get-session")
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
                                 try expect(request.url?.path == "/api/auth/list-sessions")
                                 try expect(request.httpMethod == "GET")
                                 try expect(request
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
                try expect(request.url?.path == "/api/auth/multi-session/list-device-sessions")
                try expect(request.httpMethod == "GET")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                return try response(for: request, statusCode: 200, data: encodeJSON(listedSessions))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/multi-session/set-active")
                try expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(BetterAuthSetActiveDeviceSessionRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.sessionToken == "device-token-2")
                return try response(for: request, statusCode: 200, data: encodeJSON(activeSession))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/multi-session/revoke")
                try expect(request.httpMethod == "POST")
                let payload = try JSONDecoder().decode(BetterAuthRevokeDeviceSessionRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.sessionToken == "device-token-1")
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
                try expect(request.url?.path == "/api/auth/token")
                try expect(request.httpMethod == "GET")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(BetterAuthJWT(token: "jwt-token-value")))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/jwks")
                try expect(request.httpMethod == "GET")
                try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
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
                try expect(request.url?.path == "/api/auth/two-factor/enable")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer primary-token")
                let payload = try JSONDecoder().decode(TwoFactorEnableRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.password == "password123")
                try expect(payload.issuer == "Better Auth Swift")
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(TwoFactorEnableResponse(totpURI: "otpauth://totp/Better%20Auth%20Swift:twofactor@example.com?secret=ABC123",
                                                                             backupCodes: ["backup-1", "backup-2"])))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/two-factor/verify-totp")
                let payload = try JSONDecoder().decode(TwoFactorVerifyTOTPRequest.self,
                                                       from: try #require(request.httpBody))
                try expect(payload.code == "123456")
                try expect(payload.trustDevice == true)
                return try response(for: request,
                                    statusCode: 200,
                                    data: encodeJSON(TwoFactorSessionResponse(token: "totp-token",
                                                                              user: .init(id: "user-2fa",
                                                                                          email: "twofactor@example.com",
                                                                                          name: "2FA User",
                                                                                          twoFactorEnabled: true))))
            },
            .handler { request in
                try expect(request.url?.path == "/api/auth/get-session")
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer totp-token")
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
                                                                      "message": "Invalid backup code"],
                                      operation: {
                                          _ = try await client.auth
                                              .verifyTwoFactorRecoveryCode(.init(code: "backup-invalid"))
                                      })

        await assertRequestFailedJSON(statusCode: 401, expectedJSON: ["code": "INVALID_BACKUP_CODE",
                                                                      "message": "Invalid backup code"],
                                      operation: {
                                          _ = try await client.auth
                                              .verifyTwoFactorRecoveryCode(.init(code: "backup-reused"))
                                      })
    }

    // MARK: - 2FA Disable

    @Test
    func disableTwoFactorUsesConfiguredEndpointAndPassword() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "user@example.com"))

        let transport = SequencedMockTransport([.handler { request in
            try expect(request.url?.path == "/api/auth/two-factor/disable")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
            let payload = try JSONDecoder().decode(TwoFactorDisableRequest.self,
                                                   from: try #require(request.httpBody))
            try expect(payload.password == "my-password")
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
                try expect(request.url?.path == "/api/auth/two-factor/enable")
                return try response(for: request, statusCode: 200,
                                    data: encodeJSON(TwoFactorEnableResponse(totpURI: "otpauth://totp/Example:user@example.com?secret=ABC",
                                                                             backupCodes: ["code-1", "code-2"])))
            },
            // Disable 2FA
            .handler { request in
                try expect(request.url?.path == "/api/auth/two-factor/disable")
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
            try expect(request.url?.path == "/api/auth/revoke-session")
            let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            try expect(body?["token"] as? String == "other-device-token")
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
            try expect(request.url?.path == "/api/auth/revoke-sessions")
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
}
