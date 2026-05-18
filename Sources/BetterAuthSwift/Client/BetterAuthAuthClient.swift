import Foundation

/// Public auth surface for a ``BetterAuthClient`` instance.
///
/// This facade keeps the SDK's app-facing auth interface stable while the
/// actor-isolated session manager remains an implementation detail.
public struct BetterAuthAuthClient: Sendable {
    let sessionManager: BetterAuthSessionManager

    public var onAuthStateChange: AuthEventEmitter {
        sessionManager.onAuthStateChange
    }

    public var authStateChanges: AsyncStream<AuthStateChange> {
        sessionManager.authStateChanges
    }

    public var accessTokenChanges: AsyncStream<String?> {
        sessionManager.accessTokenChanges
    }

    public var currentAuthState: AuthStateChange? {
        sessionManager.currentAuthState
    }

    public func loadStoredSession() async throws -> BetterAuthSession? {
        try await sessionManager.loadStoredSession()
    }

    public func restoreSession() async throws -> BetterAuthSession? {
        try await sessionManager.restoreSession()
    }

    public func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        try await sessionManager.restoreSessionOnLaunch()
    }

    public func restoreOrRefreshSession() async throws -> BetterAuthSession? {
        try await sessionManager.restoreOrRefreshSession()
    }

    public func currentSession() async -> BetterAuthSession? {
        await sessionManager.currentSession()
    }

    @discardableResult
    public func validSession() async throws -> BetterAuthSession {
        try await sessionManager.validSession()
    }

    public func applyRestoredSession(_ session: BetterAuthSession?) async throws {
        try await sessionManager.applyRestoredSession(session)
    }

    public func updateSession(_ session: BetterAuthSession?) async throws {
        try await sessionManager.updateSession(session)
    }

    @discardableResult
    public func refreshSession() async throws -> BetterAuthSession {
        try await sessionManager.refreshSession()
    }

    public func signOut(remotely: Bool = true) async throws {
        try await sessionManager.signOut(remotely: remotely)
    }

    @discardableResult
    public func refreshSessionIfNeeded() async throws -> BetterAuthSession {
        try await sessionManager.refreshSessionIfNeeded()
    }

    @discardableResult
    public func fetchCurrentSession() async throws -> BetterAuthSession {
        try await sessionManager.fetchCurrentSession()
    }

    public func startAutoRefresh() async {
        await sessionManager.startAutoRefresh()
    }

    public func stopAutoRefresh() async {
        await sessionManager.stopAutoRefresh()
    }

    public func shutdown() async {
        await sessionManager.shutdown()
    }

    public func applicationDidBecomeActive() async {
        await sessionManager.applicationDidBecomeActive()
    }

    public func applicationWillResignActive() async {
        await sessionManager.applicationWillResignActive()
    }

    public func parseIncomingURL(_ url: URL) async -> BetterAuthIncomingURL {
        await sessionManager.parseIncomingURL(url)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        try await sessionManager.handleIncomingURL(url)
    }

    public func handle(_ url: URL) async {
        await sessionManager.handle(url)
    }

    public func installAuthStateListeners(_ listeners: [any BetterAuthAuthStateListener]) async {
        await sessionManager.installAuthStateListeners(listeners)
    }

    public func authorizedRequest(path: String, method: String = "GET") async throws -> URLRequest {
        try await sessionManager.authorizedRequest(path: path, method: method)
    }

    func makeRelay() async -> BetterAuthSessionEventRelay {
        await sessionManager.makeRelay()
    }

    func makeMaterializer() async -> BetterAuthSessionMaterializer {
        await sessionManager.makeMaterializer()
    }
}

public extension BetterAuthAuthClient {
    @discardableResult
    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await sessionManager.signUpWithEmail(payload)
    }

    @discardableResult
    func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await sessionManager.signInWithEmail(payload)
    }

    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await sessionManager.isUsernameAvailable(payload)
    }

    @discardableResult
    func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await sessionManager.signInWithUsername(payload)
    }

    @discardableResult
    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await sessionManager.signInWithApple(payload)
    }

    @discardableResult
    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await sessionManager.signInWithSocial(payload)
    }

    @discardableResult
    func signInAnonymously() async throws -> BetterAuthSession {
        try await sessionManager.signInAnonymously()
    }

    @discardableResult
    func deleteAnonymousUser() async throws -> Bool {
        try await sessionManager.deleteAnonymousUser()
    }

    @discardableResult
    func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        try await sessionManager.deleteUser(payload)
    }

    @discardableResult
    func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await sessionManager.upgradeAnonymousWithEmail(payload)
    }

    @discardableResult
    func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await sessionManager.upgradeAnonymousWithApple(payload)
    }

    @discardableResult
    func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await sessionManager.upgradeAnonymousWithSocial(payload)
    }

    @discardableResult
    func reauthenticate(password: String) async throws -> Bool {
        try await sessionManager.reauthenticate(password: password)
    }

    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await sessionManager.beginGenericOAuth(payload)
    }

    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await sessionManager.linkGenericOAuth(payload)
    }

    @discardableResult
    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await sessionManager.completeGenericOAuth(payload)
    }

    @discardableResult
    func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await sessionManager.requestPasswordReset(payload)
    }

    @discardableResult
    func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await sessionManager.resetPassword(payload)
    }

    @discardableResult
    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        try await sessionManager.sendVerificationEmail(payload)
    }

    @discardableResult
    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await sessionManager.verifyEmail(payload)
    }

    @discardableResult
    func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await sessionManager.changeEmail(payload)
    }

    @discardableResult
    func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await sessionManager.updateUser(payload)
    }

    @discardableResult
    func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await sessionManager.changePassword(payload)
    }
}

public extension BetterAuthAuthClient {
    @discardableResult
    func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        try await sessionManager.requestMagicLink(payload)
    }

    @discardableResult
    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await sessionManager.verifyMagicLink(payload)
    }

    @discardableResult
    func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        try await sessionManager.requestEmailOTP(payload)
    }

    @discardableResult
    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await sessionManager.signInWithEmailOTP(payload)
    }

    @discardableResult
    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await sessionManager.verifyEmailOTP(payload)
    }

    @discardableResult
    func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        try await sessionManager.requestPhoneOTP(payload)
    }

    @discardableResult
    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        try await sessionManager.verifyPhoneNumber(payload)
    }

    @discardableResult
    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await sessionManager.signInWithPhoneOTP(payload)
    }

    func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await sessionManager.enableTwoFactor(payload)
    }

    @discardableResult
    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await sessionManager.verifyTwoFactorTOTP(payload)
    }

    @discardableResult
    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        try await sessionManager.sendTwoFactorOTP(payload)
    }

    @discardableResult
    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await sessionManager.verifyTwoFactorOTP(payload)
    }

    @discardableResult
    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws
        -> BetterAuthSession
    {
        try await sessionManager.verifyTwoFactorRecoveryCode(payload)
    }

    @discardableResult
    func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        try await sessionManager.disableTwoFactor(payload)
    }

    func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await sessionManager.generateTwoFactorRecoveryCodes(password: password)
    }
}

public extension BetterAuthAuthClient {
    func getSessionJWT() async throws -> BetterAuthJWT {
        try await sessionManager.getSessionJWT()
    }

    func getJWKS() async throws -> BetterAuthJWKS {
        try await sessionManager.getJWKS()
    }

    func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await sessionManager.listLinkedAccounts()
    }

    @discardableResult
    func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await sessionManager.linkSocialAccount(payload)
    }

    func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await sessionManager.passkeyRegistrationOptions(request)
    }

    func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await sessionManager.passkeyAuthenticateOptions()
    }

    @discardableResult
    func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await sessionManager.registerPasskey(payload)
    }

    @discardableResult
    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        try await sessionManager.authenticateWithPasskey(payload)
    }

    func listPasskeys() async throws -> [Passkey] {
        try await sessionManager.listPasskeys()
    }

    func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        try await sessionManager.updatePasskey(payload)
    }

    @discardableResult
    func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool {
        try await sessionManager.deletePasskey(payload)
    }
}

public extension BetterAuthAuthClient {
    func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await sessionManager.listSessions()
    }

    func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await sessionManager.listDeviceSessions()
    }

    @discardableResult
    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        try await sessionManager.setActiveDeviceSession(payload)
    }

    @discardableResult
    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        try await sessionManager.revokeDeviceSession(payload)
    }

    @discardableResult
    func revokeSession(token: String) async throws -> Bool {
        try await sessionManager.revokeSession(token: token)
    }

    @discardableResult
    func revokeSessions() async throws -> Bool {
        try await sessionManager.revokeSessions()
    }

    @discardableResult
    func revokeOtherSessions() async throws -> Bool {
        try await sessionManager.revokeOtherSessions()
    }
}

extension BetterAuthAuthClient: BetterAuthSessionLifecycle,
    BetterAuthSessionFetching,
    BetterAuthPrimaryAuthPerforming,
    BetterAuthOAuthPerforming,
    BetterAuthOneTimeCodePerforming,
    BetterAuthTwoFactorPerforming,
    BetterAuthPasskeyPerforming,
    BetterAuthAccountPerforming,
    BetterAuthSessionAdministrating {}
