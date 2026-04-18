import Foundation

public protocol BetterAuthStateObserving: Sendable {
    var authStateChanges: AsyncStream<AuthStateChange> { get }
    var onAuthStateChange: AuthEventEmitter { get }
    var currentAuthState: AuthStateChange? { get }
}

public protocol BetterAuthSessionProviding: Sendable {
    func currentSession() async -> BetterAuthSession?
}

public protocol BetterAuthSessionLifecycle: BetterAuthStateObserving, BetterAuthSessionProviding {
    func restoreSession() async throws -> BetterAuthSession?
    func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult
    func refreshSession() async throws -> BetterAuthSession
    func signOut(remotely: Bool) async throws
}

public protocol BetterAuthAuthPerforming: BetterAuthSessionLifecycle {
    func fetchCurrentSession() async throws -> BetterAuthSession
    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult
    func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession
    func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool
    func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool
    func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse
    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool
    func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession
    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession
    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult
    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse
    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse
    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession
    func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult
    func signInAnonymously() async throws -> BetterAuthSession
    func deleteAnonymousUser() async throws -> Bool
    func deleteUser(_ payload: DeleteUserRequest) async throws -> Bool
    func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult
    func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession
    func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult
    func reauthenticate(password: String) async throws -> Bool
    func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool
    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult
    func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool
    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession
    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult
    func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool
    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse
    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession
    func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse
    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest) async throws -> Bool
    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession
    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession
    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws -> BetterAuthSession
    func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool
    func generateTwoFactorRecoveryCodes(password: String) async throws -> [String]
    func passkeyRegistrationOptions(_ payload: PasskeyRegistrationOptionsRequest) async throws
        -> PasskeyRegistrationOptions
    func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions
    func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey
    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession
    func listPasskeys() async throws -> [Passkey]
    func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey
    func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool
    func sendVerificationEmail(_ payload: SendVerificationEmailRequest) async throws -> Bool
    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult
    func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool
    func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse
    func listLinkedAccounts() async throws -> [LinkedAccount]
    func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse
    func listSessions() async throws -> [BetterAuthSessionListEntry]
    func listDeviceSessions() async throws -> [BetterAuthDeviceSession]
    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws -> BetterAuthSession
    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool
    func revokeSession(token: String) async throws -> Bool
    func revokeSessions() async throws -> Bool
    func revokeOtherSessions() async throws -> Bool
    func getSessionJWT() async throws -> BetterAuthJWT
    func getJWKS() async throws -> BetterAuthJWKS
}

final class BetterAuthSessionState: @unchecked Sendable {
    let eventEmitter: AuthEventEmitter
    private let lock = NSLock()
    private var storage: BetterAuthSession?

    init(eventEmitter: AuthEventEmitter) {
        self.eventEmitter = eventEmitter
    }

    var stateChanges: AsyncStream<AuthStateChange> {
        eventEmitter.stateChanges
    }

    var latest: AuthStateChange? {
        eventEmitter.latest
    }

    var currentSession: BetterAuthSession? {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    @discardableResult
    func replaceCurrentSession(_ session: BetterAuthSession?) -> BetterAuthSession? {
        lock.lock()
        defer { lock.unlock() }
        let previous = storage
        storage = session
        return previous
    }

    func emit(_ event: AuthChangeEvent,
              session: BetterAuthSession?,
              transition: BetterAuthSessionTransition? = nil)
    {
        eventEmitter.emit(event, session: session, transition: transition)
    }
}
