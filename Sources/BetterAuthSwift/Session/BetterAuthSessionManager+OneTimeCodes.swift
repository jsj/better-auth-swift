import Foundation

public extension BetterAuthSessionManager {
    // MARK: - Magic Link

    @discardableResult
    func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        try await makeOneTimeCodeService().requestMagicLink(payload)
    }

    @discardableResult
    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await makeOneTimeCodeService().verifyMagicLink(payload)
    }

    // MARK: - Email OTP

    @discardableResult
    func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        try await makeOneTimeCodeService().requestEmailOTP(payload)
    }

    @discardableResult
    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await makeOneTimeCodeService().signInWithEmailOTP(payload)
    }

    @discardableResult
    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await makeOneTimeCodeService().verifyEmailOTP(payload, currentSession: state.currentSession)
    }

    // MARK: - Phone OTP

    @discardableResult
    func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        try await makeOneTimeCodeService().requestPhoneOTP(payload)
    }

    @discardableResult
    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        try await makeOneTimeCodeService()
            .verifyPhoneNumber(payload,
                               accessToken: payload.updatePhoneNumber == true ? state.currentSession?.session
                                   .accessToken : nil,
                               currentSession: state.currentSession)
    }

    @discardableResult
    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await makeOneTimeCodeService().signInWithPhoneOTP(payload)
    }

    // MARK: - Two Factor

    func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await makeTwoFactorService().enableTwoFactor(payload,
                                                         accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await makeTwoFactorService().verifyTwoFactorTOTP(payload)
    }

    @discardableResult
    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        try await makeTwoFactorService().sendTwoFactorOTP(payload)
    }

    @discardableResult
    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await makeTwoFactorService().verifyTwoFactorOTP(payload)
    }

    @discardableResult
    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws
        -> BetterAuthSession
    {
        try await makeTwoFactorService().verifyTwoFactorRecoveryCode(payload)
    }

    @discardableResult
    func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        try await makeTwoFactorService().disableTwoFactor(payload,
                                                          accessToken: state.currentSession?.session.accessToken)
    }

    func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await makeTwoFactorService()
            .generateTwoFactorRecoveryCodes(password: password,
                                            accessToken: state.currentSession?.session.accessToken)
    }
}
