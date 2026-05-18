import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Email + Password

    @discardableResult
    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing(status: "Signed up") { try await primaryAuth.signUpWithEmail(payload) }
    }

    func signInWithEmail(_ payload: EmailSignInRequest) async {
        await perform(status: "Signed in") {
            _ = try await primaryAuth.signInWithEmail(payload)
        }
    }

    func requestPasswordReset(_ payload: ForgotPasswordRequest) async {
        await perform(status: "Password reset email sent") {
            _ = try await primaryAuth.requestPasswordReset(payload)
        }
    }

    func resetPassword(_ payload: ResetPasswordRequest) async {
        await perform(status: "Password reset") {
            _ = try await primaryAuth.resetPassword(payload)
        }
    }

    func changePassword(_ payload: ChangePasswordRequest) async {
        await perform(status: "Password changed") {
            _ = try await accountAuth.changePassword(payload)
        }
    }

    // MARK: - Username

    @discardableResult
    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await performThrowing(status: { available in
            available ? "Username available" : "Username taken"
        }, {
            try await primaryAuth.isUsernameAvailable(payload)
        })
    }

    func signInWithUsername(_ payload: UsernameSignInRequest) async {
        await perform(status: "Signed in") {
            _ = try await primaryAuth.signInWithUsername(payload)
        }
    }

    // MARK: - Apple

    func signInWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform(status: "Signed in with Apple") {
            _ = try await primaryAuth.signInWithApple(payload)
        }
    }

    // MARK: - Social / OAuth

    @discardableResult
    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing(status: "Social sign-in initiated") {
            try await primaryAuth.signInWithSocial(payload)
        }
    }

    @discardableResult
    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await oauthAuth.beginGenericOAuth(payload)
            statusMessage = "OAuth flow started"
            return response
        }
    }

    @discardableResult
    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await oauthAuth.linkGenericOAuth(payload)
            statusMessage = "OAuth link flow started"
            return response
        }
    }

    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async {
        await perform {
            _ = try await oauthAuth.completeGenericOAuth(payload)
            statusMessage = "OAuth completed"
        }
    }

    func handleIncomingURL(_ url: URL) async {
        await perform {
            let result = try await oauthAuth.handleIncomingURL(url)
            switch result {
            case let .genericOAuth(restoredSession):
                applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                     session: restoredSession,
                                                     transition: .init(phase: .authenticated)))
                statusMessage = "OAuth completed"

            case let .magicLink(verificationResult):
                if case let .signedIn(restoredSession) = verificationResult {
                    applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                         session: restoredSession,
                                                         transition: .init(phase: .authenticated)))
                }
                statusMessage = "Magic link handled"

            case let .verifyEmail(verificationResult):
                if case let .signedIn(restoredSession) = verificationResult {
                    applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                         session: restoredSession,
                                                         transition: .init(phase: .authenticated)))
                }
                statusMessage = "Verification handled"

            case .ignored:
                statusMessage = "Ignored URL"
            }
        }
    }

    // MARK: - Anonymous

    func signInAnonymously() async {
        await perform {
            _ = try await primaryAuth.signInAnonymously()
            statusMessage = "Signed in anonymously"
        }
    }

    func deleteAnonymousUser() async {
        await perform {
            _ = try await primaryAuth.deleteAnonymousUser()
            statusMessage = "Anonymous user deleted"
        }
    }

    // MARK: - Delete User

    func deleteUser(_ payload: DeleteUserRequest = .init()) async {
        await perform {
            _ = try await primaryAuth.deleteUser(payload)
            statusMessage = "Account deleted"
        }
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing {
            let result = try await primaryAuth.upgradeAnonymousWithEmail(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform {
            _ = try await primaryAuth.upgradeAnonymousWithApple(payload)
            statusMessage = "Account upgraded with Apple"
        }
    }

    @discardableResult
    func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing {
            let result = try await primaryAuth.upgradeAnonymousWithSocial(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    // MARK: - Re-authentication

    @discardableResult
    func reauthenticate(password: String) async throws -> Bool {
        try await performThrowing {
            let result = try await primaryAuth.reauthenticate(password: password)
            statusMessage = "Re-authenticated"
            return result
        }
    }
}
