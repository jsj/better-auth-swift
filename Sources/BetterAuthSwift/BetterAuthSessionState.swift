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
    private(set) var currentSession: BetterAuthSession?

    init(eventEmitter: AuthEventEmitter) {
        self.eventEmitter = eventEmitter
    }

    var stateChanges: AsyncStream<AuthStateChange> {
        eventEmitter.stateChanges
    }

    var latest: AuthStateChange? {
        eventEmitter.latest
    }

    func replaceCurrentSession(_ session: BetterAuthSession?) {
        currentSession = session
    }

    func emit(_ event: AuthChangeEvent,
              session: BetterAuthSession?,
              transition: BetterAuthSessionTransition? = nil)
    {
        eventEmitter.emit(event, session: session, transition: transition)
    }
}

public struct BetterAuthSessionLifecycleAdapter: BetterAuthAuthPerforming {
    private let manager: BetterAuthSessionManager

    init(manager: BetterAuthSessionManager) {
        self.manager = manager
    }

    public var authStateChanges: AsyncStream<AuthStateChange> {
        manager.authStateChanges
    }

    public var onAuthStateChange: AuthEventEmitter {
        manager.onAuthStateChange
    }

    public var currentAuthState: AuthStateChange? {
        manager.currentAuthState
    }

    public func currentSession() async -> BetterAuthSession? {
        await manager.currentSession()
    }

    public func restoreSession() async throws -> BetterAuthSession? {
        try await manager.restoreSession()
    }

    public func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        try await manager.restoreSessionOnLaunch()
    }

    public func refreshSession() async throws -> BetterAuthSession {
        try await manager.refreshSession()
    }

    public func signOut(remotely: Bool) async throws {
        try await manager.signOut(remotely: remotely)
    }

    public func fetchCurrentSession() async throws -> BetterAuthSession {
        try await manager.fetchCurrentSession()
    }

    public func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await manager.signUpWithEmail(payload)
    }

    public func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await manager.signInWithEmail(payload)
    }

    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await manager.requestPasswordReset(payload)
    }

    public func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await manager.resetPassword(payload)
    }

    public func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await manager.changePassword(payload)
    }

    public func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await manager.isUsernameAvailable(payload)
    }

    public func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await manager.signInWithUsername(payload)
    }

    public func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await manager.signInWithApple(payload)
    }

    public func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await manager.signInWithSocial(payload)
    }

    public func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await manager.beginGenericOAuth(payload)
    }

    public func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await manager.linkGenericOAuth(payload)
    }

    public func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await manager.completeGenericOAuth(payload)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        try await manager.handleIncomingURL(url)
    }

    public func signInAnonymously() async throws -> BetterAuthSession {
        try await manager.signInAnonymously()
    }

    public func deleteAnonymousUser() async throws -> Bool {
        try await manager.deleteAnonymousUser()
    }

    public func deleteUser(_ payload: DeleteUserRequest) async throws -> Bool {
        try await manager.deleteUser(payload)
    }

    public func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await manager.upgradeAnonymousWithEmail(payload)
    }

    public func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await manager.upgradeAnonymousWithApple(payload)
    }

    public func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await manager.upgradeAnonymousWithSocial(payload)
    }

    public func reauthenticate(password: String) async throws -> Bool {
        try await manager.reauthenticate(password: password)
    }

    public func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        try await manager.requestMagicLink(payload)
    }

    public func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await manager.verifyMagicLink(payload)
    }

    public func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        try await manager.requestEmailOTP(payload)
    }

    public func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await manager.signInWithEmailOTP(payload)
    }

    public func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await manager.verifyEmailOTP(payload)
    }

    public func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        try await manager.requestPhoneOTP(payload)
    }

    public func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        try await manager.verifyPhoneNumber(payload)
    }

    public func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await manager.signInWithPhoneOTP(payload)
    }

    public func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await manager.enableTwoFactor(payload)
    }

    public func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest) async throws -> Bool {
        try await manager.sendTwoFactorOTP(payload)
    }

    public func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await manager.verifyTwoFactorTOTP(payload)
    }

    public func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await manager.verifyTwoFactorOTP(payload)
    }

    public func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws
        -> BetterAuthSession
    {
        try await manager.verifyTwoFactorRecoveryCode(payload)
    }

    public func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        try await manager.disableTwoFactor(payload)
    }

    public func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await manager.generateTwoFactorRecoveryCodes(password: password)
    }

    public func passkeyRegistrationOptions(_ payload: PasskeyRegistrationOptionsRequest) async throws
        -> PasskeyRegistrationOptions
    {
        try await manager.passkeyRegistrationOptions(payload)
    }

    public func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await manager.passkeyAuthenticateOptions()
    }

    public func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await manager.registerPasskey(payload)
    }

    public func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        try await manager.authenticateWithPasskey(payload)
    }

    public func listPasskeys() async throws -> [Passkey] {
        try await manager.listPasskeys()
    }

    public func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        try await manager.updatePasskey(payload)
    }

    public func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool {
        try await manager.deletePasskey(payload)
    }

    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest) async throws -> Bool {
        try await manager.sendVerificationEmail(payload)
    }

    public func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await manager.verifyEmail(payload)
    }

    public func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await manager.changeEmail(payload)
    }

    public func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await manager.updateUser(payload)
    }

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await manager.listLinkedAccounts()
    }

    public func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await manager.linkSocialAccount(payload)
    }

    public func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await manager.listSessions()
    }

    public func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await manager.listDeviceSessions()
    }

    public func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        try await manager.setActiveDeviceSession(payload)
    }

    public func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        try await manager.revokeDeviceSession(payload)
    }

    public func revokeSession(token: String) async throws -> Bool {
        try await manager.revokeSession(token: token)
    }

    public func revokeSessions() async throws -> Bool {
        try await manager.revokeSessions()
    }

    public func revokeOtherSessions() async throws -> Bool {
        try await manager.revokeOtherSessions()
    }

    public func getSessionJWT() async throws -> BetterAuthJWT {
        try await manager.getSessionJWT()
    }

    public func getJWKS() async throws -> BetterAuthJWKS {
        try await manager.getJWKS()
    }
}
