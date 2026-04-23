import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Email + Password

    @discardableResult
    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing {
            let result = try await auth.signUpWithEmail(payload)
            statusMessage = "Signed up"
            return result
        }
    }

    func signInWithEmail(_ payload: EmailSignInRequest) async {
        await perform {
            _ = try await auth.signInWithEmail(payload)
            statusMessage = "Signed in"
        }
    }

    func requestPasswordReset(_ payload: ForgotPasswordRequest) async {
        await perform {
            _ = try await auth.requestPasswordReset(payload)
            statusMessage = "Password reset email sent"
        }
    }

    func resetPassword(_ payload: ResetPasswordRequest) async {
        await perform {
            _ = try await auth.resetPassword(payload)
            statusMessage = "Password reset"
        }
    }

    func changePassword(_ payload: ChangePasswordRequest) async {
        await perform {
            _ = try await auth.changePassword(payload)
            statusMessage = "Password changed"
        }
    }

    // MARK: - Username

    @discardableResult
    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await performThrowing {
            let available = try await auth.isUsernameAvailable(payload)
            statusMessage = available ? "Username available" : "Username taken"
            return available
        }
    }

    func signInWithUsername(_ payload: UsernameSignInRequest) async {
        await perform {
            _ = try await auth.signInWithUsername(payload)
            statusMessage = "Signed in"
        }
    }

    // MARK: - Apple

    func signInWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform {
            _ = try await auth.signInWithApple(payload)
            statusMessage = "Signed in with Apple"
        }
    }

    // MARK: - Social / OAuth

    @discardableResult
    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing {
            let result = try await auth.signInWithSocial(payload)
            statusMessage = "Social sign-in initiated"
            return result
        }
    }

    @discardableResult
    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await auth.beginGenericOAuth(payload)
            statusMessage = "OAuth flow started"
            return response
        }
    }

    @discardableResult
    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await auth.linkGenericOAuth(payload)
            statusMessage = "OAuth link flow started"
            return response
        }
    }

    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async {
        await perform {
            _ = try await auth.completeGenericOAuth(payload)
            statusMessage = "OAuth completed"
        }
    }

    func handleIncomingURL(_ url: URL) async {
        await perform {
            let result = try await auth.handleIncomingURL(url)
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

            @unknown default:
                statusMessage = "Unhandled URL result"
            }
        }
    }

    // MARK: - Anonymous

    func signInAnonymously() async {
        await perform {
            _ = try await auth.signInAnonymously()
            statusMessage = "Signed in anonymously"
        }
    }

    func deleteAnonymousUser() async {
        await perform {
            _ = try await auth.deleteAnonymousUser()
            statusMessage = "Anonymous user deleted"
        }
    }

    // MARK: - Delete User

    func deleteUser(_ payload: DeleteUserRequest = .init()) async {
        await perform {
            _ = try await auth.deleteUser(payload)
            statusMessage = "Account deleted"
        }
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing {
            let result = try await auth.upgradeAnonymousWithEmail(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform {
            _ = try await auth.upgradeAnonymousWithApple(payload)
            statusMessage = "Account upgraded with Apple"
        }
    }

    @discardableResult
    func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing {
            let result = try await auth.upgradeAnonymousWithSocial(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    // MARK: - Re-authentication

    @discardableResult
    func reauthenticate(password: String) async throws -> Bool {
        try await performThrowing {
            let result = try await auth.reauthenticate(password: password)
            statusMessage = "Re-authenticated"
            return result
        }
    }
}
