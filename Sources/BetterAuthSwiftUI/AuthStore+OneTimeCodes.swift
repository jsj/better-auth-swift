import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Magic Link

    func requestMagicLink(_ payload: MagicLinkRequest) async {
        await perform {
            _ = try await auth.requestMagicLink(payload)
            statusMessage = "Magic link sent"
        }
    }

    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async {
        await perform {
            let result = try await auth.verifyMagicLink(payload)
            if case let .signedIn(session) = result {
                applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                     session: session,
                                                     transition: .init(phase: .authenticated)))
            }
            statusMessage = "Magic link verified"
        }
    }

    // MARK: - Email OTP

    func requestEmailOTP(_ payload: EmailOTPRequest) async {
        await perform {
            _ = try await auth.requestEmailOTP(payload)
            statusMessage = "Email OTP sent"
        }
    }

    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async {
        await perform {
            _ = try await auth.signInWithEmailOTP(payload)
            statusMessage = "Signed in with email OTP"
        }
    }

    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async {
        await perform {
            let result = try await auth.verifyEmailOTP(payload)
            if case let .signedIn(session) = result {
                applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                     session: session,
                                                     transition: .init(phase: .authenticated)))
            }
            statusMessage = "Email OTP verified"
        }
    }

    // MARK: - Phone OTP

    func requestPhoneOTP(_ payload: PhoneOTPRequest) async {
        await perform {
            _ = try await auth.requestPhoneOTP(payload)
            statusMessage = "Phone OTP sent"
        }
    }

    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async {
        await perform {
            _ = try await auth.verifyPhoneNumber(payload)
            statusMessage = "Phone number verified"
        }
    }

    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async {
        await perform {
            _ = try await auth.signInWithPhoneOTP(payload)
            statusMessage = "Signed in with phone OTP"
        }
    }

    // MARK: - Two Factor

    @discardableResult
    func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await performThrowing {
            let response = try await auth.enableTwoFactor(payload)
            statusMessage = "Two-factor enabled"
            return response
        }
    }

    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async {
        await perform {
            _ = try await auth.sendTwoFactorOTP(payload)
            statusMessage = "Two-factor OTP sent"
        }
    }

    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorTOTP(payload)
            statusMessage = "Two-factor TOTP verified"
        }
    }

    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorOTP(payload)
            statusMessage = "Two-factor OTP verified"
        }
    }

    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorRecoveryCode(payload)
            statusMessage = "Recovery code accepted"
        }
    }

    func disableTwoFactor(_ payload: TwoFactorDisableRequest) async {
        await perform {
            _ = try await auth.disableTwoFactor(payload)
            statusMessage = "Two-factor disabled"
        }
    }

    @discardableResult
    func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await performThrowing {
            let codes = try await auth.generateTwoFactorRecoveryCodes(password: password)
            statusMessage = "Backup codes generated"
            return codes
        }
    }
}
