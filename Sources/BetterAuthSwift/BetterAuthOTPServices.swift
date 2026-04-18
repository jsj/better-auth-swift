import Foundation

struct BetterAuthOneTimeCodeService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.magicLink.signInPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        let result: MagicLinkVerificationResult = try await context.network
            .get(path: context.configuration.endpoints.magicLink.verifyPath,
                 queryItems: [URLQueryItem(name: "token", value: payload.token),
                              URLQueryItem(name: "callbackURL", value: payload.callbackURL),
                              URLQueryItem(name: "newUserCallbackURL", value: payload.newUserCallbackURL),
                              URLQueryItem(name: "errorCallbackURL", value: payload.errorCallbackURL)],
                 accessToken: nil)
        if case let .signedIn(session) = result {
            _ = try relay.setSession(session, event: .signedIn)
        }
        return result
    }

    func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        let response: EmailOTPRequestResponse = try await context.network
            .post(path: context.configuration.endpoints.emailOTP.requestPath,
                  body: payload,
                  accessToken: nil)
        return response.success
    }

    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.emailOTP.signInPath,
                  body: payload,
                  accessToken: nil)
        if let session = response.materializedSession {
            _ = try relay.setSession(session, event: .signedIn)
            return session
        }
        if let signedIn = response.signedIn {
            let session = try await materializer.materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            _ = try relay.setSession(session, event: .signedIn)
            return session
        }
        throw BetterAuthError.invalidResponse
    }

    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest,
                        currentSession: BetterAuthSession?) async throws -> EmailOTPVerifyResult
    {
        let result: EmailOTPVerifyResult = try await context.network
            .post(path: context.configuration.endpoints.emailOTP.verifyPath,
                  body: payload,
                  accessToken: nil)
        if case let .signedIn(session) = result {
            _ = try relay.setSession(session, event: .signedIn)
        } else if case let .verified(user) = result, let currentSession, currentSession.user.id == user.id {
            _ = try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                       user: currentSession.user.merged(with: user)),
                                     event: .userUpdated)
        }
        return result
    }

    func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        let response: PhoneOTPRequestResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTP.requestPath,
                  body: payload,
                  accessToken: nil)
        if let success = response.success { return success }
        if let status = response.status { return status }
        throw BetterAuthError.invalidResponse
    }

    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest,
                           accessToken: String?,
                           currentSession: BetterAuthSession?) async throws -> PhoneOTPVerifyResponse
    {
        let response: PhoneOTPVerifyResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTP.verifyPath,
                  body: payload,
                  accessToken: accessToken)
        if let token = response.token, let user = response.user {
            let twoFactorUser = TwoFactorUser(id: user.id,
                                              email: user.email,
                                              name: user.name,
                                              username: user.username,
                                              displayUsername: user.displayUsername,
                                              twoFactorEnabled: false)
            let session = try await materializer.materializeSession(token: token, fallbackUser: twoFactorUser)
            _ = try relay.setSession(session, event: .signedIn)
        } else if let user = response.user, let currentSession, currentSession.user.id == user.id {
            _ = try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                       user: currentSession.user.merged(with: user)),
                                     event: .userUpdated)
        }
        return response
    }

    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTP.signInPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }
}

struct BetterAuthTwoFactorService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func enableTwoFactor(_ payload: TwoFactorEnableRequest,
                         accessToken: String?) async throws -> TwoFactorEnableResponse
    {
        try await context.network.post(path: context.configuration.endpoints.twoFactor.enablePath,
                                       body: payload,
                                       accessToken: accessToken)
    }

    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.verifyTOTPPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        let response: TwoFactorChallengeStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.sendOTPPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.verifyOTPPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.verifyBackupCodePath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func disableTwoFactor(_ payload: TwoFactorDisableRequest,
                          accessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.disablePath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func generateTwoFactorRecoveryCodes(password: String,
                                        accessToken: String?) async throws -> [String]
    {
        struct Request: Encodable, Sendable { let password: String }
        let response: TwoFactorGenerateBackupCodesResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactor.generateBackupCodesPath,
                  body: Request(password: password),
                  accessToken: accessToken)
        return response.backupCodes
    }
}
