import Foundation

public extension BetterAuthAuthClient {
    var lifecycle: BetterAuthSessionLifecycleClient {
        BetterAuthSessionLifecycleClient(auth: self)
    }

    var email: BetterAuthEmailAuthClient {
        BetterAuthEmailAuthClient(auth: self)
    }

    var username: BetterAuthUsernameAuthClient {
        BetterAuthUsernameAuthClient(auth: self)
    }

    var apple: BetterAuthAppleAuthClient {
        BetterAuthAppleAuthClient(auth: self)
    }

    var social: BetterAuthSocialAuthClient {
        BetterAuthSocialAuthClient(auth: self)
    }

    var anonymous: BetterAuthAnonymousAuthClient {
        BetterAuthAnonymousAuthClient(auth: self)
    }

    var oauth: BetterAuthOAuthClient {
        BetterAuthOAuthClient(auth: self)
    }

    var emailOTP: BetterAuthEmailOTPClient {
        BetterAuthEmailOTPClient(auth: self)
    }

    var phoneOTP: BetterAuthPhoneOTPClient {
        BetterAuthPhoneOTPClient(auth: self)
    }

    var twoFactor: BetterAuthTwoFactorClient {
        BetterAuthTwoFactorClient(auth: self)
    }

    var passkeys: BetterAuthPasskeyClient {
        BetterAuthPasskeyClient(auth: self)
    }

    var account: BetterAuthAccountClient {
        BetterAuthAccountClient(auth: self)
    }

    var sessions: BetterAuthSessionsClient {
        BetterAuthSessionsClient(auth: self)
    }
}

public struct BetterAuthSessionLifecycleClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public var onAuthStateChange: AuthEventEmitter {
        auth.onAuthStateChange
    }

    public var authStateChanges: AsyncStream<AuthStateChange> {
        auth.authStateChanges
    }

    public var accessTokenChanges: AsyncStream<String?> {
        auth.accessTokenChanges
    }

    public var currentAuthState: AuthStateChange? {
        auth.currentAuthState
    }

    public func restoreOnLaunch() async throws -> BetterAuthRestoreResult {
        try await auth.restoreSessionOnLaunch()
    }

    public func restoreOrRefresh() async throws -> BetterAuthSession? {
        try await auth.restoreOrRefreshSession()
    }

    public func current() async -> BetterAuthSession? {
        await auth.currentSession()
    }

    @discardableResult
    public func valid() async throws -> BetterAuthSession {
        try await auth.validSession()
    }

    @discardableResult
    public func refresh() async throws -> BetterAuthSession {
        try await auth.refreshSession()
    }

    @discardableResult
    public func refreshIfNeeded() async throws -> BetterAuthSession {
        try await auth.refreshSessionIfNeeded()
    }

    @discardableResult
    public func fetchCurrent() async throws -> BetterAuthSession {
        try await auth.fetchCurrentSession()
    }

    public func signOut(remotely: Bool = true) async throws {
        try await auth.signOut(remotely: remotely)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        try await auth.handleIncomingURL(url)
    }
}

public struct BetterAuthEmailAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func signUp(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await auth.signUpWithEmail(payload)
    }

    @discardableResult
    public func signIn(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await auth.signInWithEmail(payload)
    }

    @discardableResult
    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await auth.requestPasswordReset(payload)
    }

    @discardableResult
    public func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await auth.resetPassword(payload)
    }
}

public struct BetterAuthUsernameAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public func isAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await auth.isUsernameAvailable(payload)
    }

    @discardableResult
    public func signIn(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await auth.signInWithUsername(payload)
    }
}

public struct BetterAuthAppleAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func signIn(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await auth.signInWithApple(payload)
    }
}

public struct BetterAuthSocialAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func signIn(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await auth.signInWithSocial(payload)
    }

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await auth.listLinkedAccounts()
    }

    @discardableResult
    public func linkAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await auth.linkSocialAccount(payload)
    }
}

public struct BetterAuthAnonymousAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func signIn() async throws -> BetterAuthSession {
        try await auth.signInAnonymously()
    }

    @discardableResult
    public func deleteUser() async throws -> Bool {
        try await auth.deleteAnonymousUser()
    }

    @discardableResult
    public func upgradeWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await auth.upgradeAnonymousWithEmail(payload)
    }

    @discardableResult
    public func upgradeWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await auth.upgradeAnonymousWithApple(payload)
    }

    @discardableResult
    public func upgradeWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await auth.upgradeAnonymousWithSocial(payload)
    }
}

public struct BetterAuthOAuthClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public func begin(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await auth.beginGenericOAuth(payload)
    }

    public func link(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await auth.linkGenericOAuth(payload)
    }

    @discardableResult
    public func complete(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await auth.completeGenericOAuth(payload)
    }
}

public struct BetterAuthEmailOTPClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func request(_ payload: EmailOTPRequest) async throws -> Bool {
        try await auth.requestEmailOTP(payload)
    }

    @discardableResult
    public func signIn(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await auth.signInWithEmailOTP(payload)
    }

    @discardableResult
    public func verify(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await auth.verifyEmailOTP(payload)
    }
}

public struct BetterAuthPhoneOTPClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func request(_ payload: PhoneOTPRequest) async throws -> Bool {
        try await auth.requestPhoneOTP(payload)
    }

    @discardableResult
    public func verifyNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        try await auth.verifyPhoneNumber(payload)
    }

    @discardableResult
    public func signIn(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await auth.signInWithPhoneOTP(payload)
    }
}

public struct BetterAuthTwoFactorClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public func enable(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await auth.enableTwoFactor(payload)
    }

    @discardableResult
    public func sendOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        try await auth.sendTwoFactorOTP(payload)
    }

    @discardableResult
    public func verifyTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await auth.verifyTwoFactorTOTP(payload)
    }

    @discardableResult
    public func verifyOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await auth.verifyTwoFactorOTP(payload)
    }

    @discardableResult
    public func verifyRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws -> BetterAuthSession {
        try await auth.verifyTwoFactorRecoveryCode(payload)
    }

    @discardableResult
    public func disable(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        try await auth.disableTwoFactor(payload)
    }

    public func generateRecoveryCodes(password: String) async throws -> [String] {
        try await auth.generateTwoFactorRecoveryCodes(password: password)
    }
}

public struct BetterAuthPasskeyClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public func registrationOptions(_ payload: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await auth.passkeyRegistrationOptions(payload)
    }

    public func authenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await auth.passkeyAuthenticateOptions()
    }

    @discardableResult
    public func register(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await auth.registerPasskey(payload)
    }

    @discardableResult
    public func authenticate(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        try await auth.authenticateWithPasskey(payload)
    }

    public func list() async throws -> [Passkey] {
        try await auth.listPasskeys()
    }

    public func update(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        try await auth.updatePasskey(payload)
    }

    @discardableResult
    public func delete(_ payload: DeletePasskeyRequest) async throws -> Bool {
        try await auth.deletePasskey(payload)
    }
}

public struct BetterAuthAccountClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    @discardableResult
    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        try await auth.sendVerificationEmail(payload)
    }

    @discardableResult
    public func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await auth.verifyEmail(payload)
    }

    @discardableResult
    public func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await auth.changeEmail(payload)
    }

    @discardableResult
    public func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await auth.updateUser(payload)
    }

    @discardableResult
    public func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await auth.changePassword(payload)
    }

    @discardableResult
    public func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        try await auth.deleteUser(payload)
    }

    @discardableResult
    public func reauthenticate(password: String) async throws -> Bool {
        try await auth.reauthenticate(password: password)
    }
}

public struct BetterAuthSessionsClient: Sendable {
    private let auth: BetterAuthAuthClient

    init(auth: BetterAuthAuthClient) {
        self.auth = auth
    }

    public func list() async throws -> [BetterAuthSessionListEntry] {
        try await auth.listSessions()
    }

    public func listDevices() async throws -> [BetterAuthDeviceSession] {
        try await auth.listDeviceSessions()
    }

    @discardableResult
    public func setActiveDevice(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        try await auth.setActiveDeviceSession(payload)
    }

    @discardableResult
    public func revokeDevice(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        try await auth.revokeDeviceSession(payload)
    }

    @discardableResult
    public func revoke(token: String) async throws -> Bool {
        try await auth.revokeSession(token: token)
    }

    @discardableResult
    public func revokeAll() async throws -> Bool {
        try await auth.revokeSessions()
    }

    @discardableResult
    public func revokeOthers() async throws -> Bool {
        try await auth.revokeOtherSessions()
    }

    public func jwt() async throws -> BetterAuthJWT {
        try await auth.getSessionJWT()
    }

    public func jwks() async throws -> BetterAuthJWKS {
        try await auth.getJWKS()
    }
}
