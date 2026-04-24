import Foundation

public extension BetterAuthSessionManager {
    // MARK: - Email + Password

    @discardableResult
    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await throttleAuthOperation("signUpWithEmail")
        return try await makePrimaryAuthService().signUpWithEmail(payload)
    }

    @discardableResult
    func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await throttleAuthOperation("signInWithEmail")
        return try await makePrimaryAuthService().signInWithEmail(payload)
    }

    // MARK: - Username

    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await makePrimaryAuthService().isUsernameAvailable(payload)
    }

    @discardableResult
    func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await throttleAuthOperation("signInWithUsername")
        return try await makePrimaryAuthService().signInWithUsername(payload)
    }

    // MARK: - Apple

    @discardableResult
    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await throttleAuthOperation("signInWithApple")
        return try await makePrimaryAuthService().signInWithApple(payload)
    }

    // MARK: - Social

    @discardableResult
    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await throttleAuthOperation("signInWithSocial")
        return try await makePrimaryAuthService().signInWithSocial(payload)
    }

    // MARK: - Anonymous

    @discardableResult
    func signInAnonymously() async throws -> BetterAuthSession {
        try await throttleAuthOperation("signInAnonymously")
        return try await makePrimaryAuthService().signInAnonymously()
    }

    @discardableResult
    func deleteAnonymousUser() async throws -> Bool {
        try await makePrimaryAuthService().deleteAnonymousUser(accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Delete User

    @discardableResult
    func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        try await makePrimaryAuthService().deleteUser(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signUpWithEmail(payload)
    }

    @discardableResult
    func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signInWithApple(payload)
    }

    @discardableResult
    func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signInWithSocial(payload)
    }

    // MARK: - Re-authentication

    @discardableResult
    func reauthenticate(password: String) async throws -> Bool {
        try await throttleAuthOperation("reauthenticate")
        return try await makePrimaryAuthService().reauthenticate(password: password,
                                                                 currentSession: state.currentSession)
    }

    // MARK: - Generic OAuth

    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await makeOAuthService().beginGenericOAuth(payload)
    }

    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await makeOAuthService().linkGenericOAuth(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await makeOAuthService().completeGenericOAuth(payload,
                                                          accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Password Reset

    @discardableResult
    func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await makePrimaryAuthService().requestPasswordReset(payload)
    }

    @discardableResult
    func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await makePrimaryAuthService().resetPassword(payload)
    }

    // MARK: - Email Verification

    @discardableResult
    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        try await makeProfileService().sendVerificationEmail(payload,
                                                             accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await makeProfileService().verifyEmail(payload)
    }

    @discardableResult
    func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await makeProfileService().changeEmail(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - User Management

    @discardableResult
    func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await makeProfileService().updateUser(payload, currentSession: state.currentSession)
    }

    @discardableResult
    func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await makeProfileService().changePassword(payload, currentSession: state.currentSession)
    }
}
