import BetterAuth
import Foundation

public struct AuthStoreViewState: Sendable, Equatable {
    public let session: BetterAuthSession?
    public let launchState: AuthLaunchState
    public let isLoading: Bool
    public let statusMessage: String?
    public let errorMessage: String?

    public var isAuthenticated: Bool {
        session != nil
    }

    public var user: BetterAuthSession.User? {
        session?.user
    }

    public init(session: BetterAuthSession?,
                launchState: AuthLaunchState,
                isLoading: Bool,
                statusMessage: String?,
                errorMessage: String?)
    {
        self.session = session
        self.launchState = launchState
        self.isLoading = isLoading
        self.statusMessage = statusMessage
        self.errorMessage = errorMessage
    }
}

public extension AuthStore {
    var viewState: AuthStoreViewState {
        AuthStoreViewState(session: session,
                           launchState: launchState,
                           isLoading: isLoading,
                           statusMessage: statusMessage,
                           errorMessage: lastUnderlyingError?.localizedDescription)
    }

    var lifecycle: AuthStoreLifecycleNamespace {
        AuthStoreLifecycleNamespace(store: self)
    }

    var email: AuthStoreEmailNamespace {
        AuthStoreEmailNamespace(store: self)
    }

    var username: AuthStoreUsernameNamespace {
        AuthStoreUsernameNamespace(store: self)
    }

    var apple: AuthStoreAppleNamespace {
        AuthStoreAppleNamespace(store: self)
    }

    var social: AuthStoreSocialNamespace {
        AuthStoreSocialNamespace(store: self)
    }

    var anonymous: AuthStoreAnonymousNamespace {
        AuthStoreAnonymousNamespace(store: self)
    }

    var oauth: AuthStoreOAuthNamespace {
        AuthStoreOAuthNamespace(store: self)
    }

    var emailOTP: AuthStoreEmailOTPNamespace {
        AuthStoreEmailOTPNamespace(store: self)
    }

    var phoneOTP: AuthStorePhoneOTPNamespace {
        AuthStorePhoneOTPNamespace(store: self)
    }

    var twoFactor: AuthStoreTwoFactorNamespace {
        AuthStoreTwoFactorNamespace(store: self)
    }

    var passkeys: AuthStorePasskeyNamespace {
        AuthStorePasskeyNamespace(store: self)
    }

    var account: AuthStoreAccountNamespace {
        AuthStoreAccountNamespace(store: self)
    }

    var sessions: AuthStoreSessionsNamespace {
        AuthStoreSessionsNamespace(store: self)
    }
}

@MainActor
public struct AuthStoreLifecycleNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func bootstrap() async {
        await store.bootstrap()
    }

    public func restore() async {
        await store.restore()
    }

    public func refresh() async {
        await store.refresh()
    }

    public func fetchCurrentSession() async {
        await store.fetchCurrentSession()
    }

    public func signOut(remotely: Bool = true) async {
        await store.signOut(remotely: remotely)
    }

    public func shutdown() {
        store.shutdown()
    }
}

@MainActor
public struct AuthStoreEmailNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    @discardableResult
    public func signUp(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await store.signUpWithEmail(payload)
    }

    public func signIn(_ payload: EmailSignInRequest) async {
        await store.signInWithEmail(payload)
    }

    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async {
        await store.requestPasswordReset(payload)
    }

    public func resetPassword(_ payload: ResetPasswordRequest) async {
        await store.resetPassword(payload)
    }
}

@MainActor
public struct AuthStoreUsernameNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    @discardableResult
    public func isAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await store.isUsernameAvailable(payload)
    }

    public func signIn(_ payload: UsernameSignInRequest) async {
        await store.signInWithUsername(payload)
    }
}

@MainActor
public struct AuthStoreAppleNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func signIn(_ payload: AppleNativeSignInPayload) async {
        await store.signInWithApple(payload)
    }
}

@MainActor
public struct AuthStoreSocialNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    @discardableResult
    public func signIn(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await store.signInWithSocial(payload)
    }

    @discardableResult
    public func linkAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await store.linkSocialAccount(payload)
    }

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await store.listLinkedAccounts()
    }
}

@MainActor
public struct AuthStoreAnonymousNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func signIn() async {
        await store.signInAnonymously()
    }

    public func deleteUser() async {
        await store.deleteAnonymousUser()
    }

    @discardableResult
    public func upgradeWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await store.upgradeAnonymousWithEmail(payload)
    }

    public func upgradeWithApple(_ payload: AppleNativeSignInPayload) async {
        await store.upgradeAnonymousWithApple(payload)
    }

    @discardableResult
    public func upgradeWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await store.upgradeAnonymousWithSocial(payload)
    }
}

@MainActor
public struct AuthStoreOAuthNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func begin(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await store.beginGenericOAuth(payload)
    }

    public func link(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await store.linkGenericOAuth(payload)
    }

    public func complete(_ payload: GenericOAuthCallbackRequest) async {
        await store.completeGenericOAuth(payload)
    }

    public func handleIncomingURL(_ url: URL) async {
        await store.handleIncomingURL(url)
    }
}

@MainActor
public struct AuthStoreEmailOTPNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func request(_ payload: EmailOTPRequest) async {
        await store.requestEmailOTP(payload)
    }

    public func signIn(_ payload: EmailOTPSignInRequest) async {
        await store.signInWithEmailOTP(payload)
    }

    public func verify(_ payload: EmailOTPVerifyRequest) async {
        await store.verifyEmailOTP(payload)
    }
}

@MainActor
public struct AuthStorePhoneOTPNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func request(_ payload: PhoneOTPRequest) async {
        await store.requestPhoneOTP(payload)
    }

    public func verifyNumber(_ payload: PhoneOTPVerifyRequest) async {
        await store.verifyPhoneNumber(payload)
    }

    public func signIn(_ payload: PhoneOTPSignInRequest) async {
        await store.signInWithPhoneOTP(payload)
    }
}

@MainActor
public struct AuthStoreTwoFactorNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    @discardableResult
    public func enable(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await store.enableTwoFactor(payload)
    }

    public func sendOTP(_ payload: TwoFactorSendOTPRequest = .init()) async {
        await store.sendTwoFactorOTP(payload)
    }

    public func verifyTOTP(_ payload: TwoFactorVerifyTOTPRequest) async {
        await store.verifyTwoFactorTOTP(payload)
    }

    public func verifyOTP(_ payload: TwoFactorVerifyOTPRequest) async {
        await store.verifyTwoFactorOTP(payload)
    }

    public func verifyRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async {
        await store.verifyTwoFactorRecoveryCode(payload)
    }

    public func disable(_ payload: TwoFactorDisableRequest) async {
        await store.disableTwoFactor(payload)
    }

    public func generateRecoveryCodes(password: String) async throws -> [String] {
        try await store.generateTwoFactorRecoveryCodes(password: password)
    }
}

@MainActor
public struct AuthStorePasskeyNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func registrationOptions(_ payload: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await store.passkeyRegistrationOptions(payload)
    }

    public func authenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await store.passkeyAuthenticateOptions()
    }

    public func register(_ payload: PasskeyRegistrationRequest) async {
        await store.registerPasskey(payload)
    }

    public func authenticate(_ payload: PasskeyAuthenticationRequest) async {
        await store.authenticateWithPasskey(payload)
    }

    public func list() async throws -> [Passkey] {
        try await store.listPasskeys()
    }

    public func update(_ payload: UpdatePasskeyRequest) async {
        await store.updatePasskey(payload)
    }

    public func delete(_ payload: DeletePasskeyRequest) async {
        await store.deletePasskey(payload)
    }
}

@MainActor
public struct AuthStoreAccountNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async {
        await store.sendVerificationEmail(payload)
    }

    public func verifyEmail(_ payload: VerifyEmailRequest) async {
        await store.verifyEmail(payload)
    }

    public func changeEmail(_ payload: ChangeEmailRequest) async {
        await store.changeEmail(payload)
    }

    public func updateUser(_ payload: UpdateUserRequest) async {
        await store.updateUser(payload)
    }

    public func changePassword(_ payload: ChangePasswordRequest) async {
        await store.changePassword(payload)
    }

    public func deleteUser(_ payload: DeleteUserRequest = .init()) async {
        await store.deleteUser(payload)
    }

    @discardableResult
    public func reauthenticate(password: String) async throws -> Bool {
        try await store.reauthenticate(password: password)
    }
}

@MainActor
public struct AuthStoreSessionsNamespace {
    private let store: AuthStore

    init(store: AuthStore) {
        self.store = store
    }

    public func list() async throws -> [BetterAuthSessionListEntry] {
        try await store.listSessions()
    }

    public func listDevices() async throws -> [BetterAuthDeviceSession] {
        try await store.listDeviceSessions()
    }

    public func setActiveDevice(_ payload: BetterAuthSetActiveDeviceSessionRequest) async {
        await store.setActiveDeviceSession(payload)
    }

    public func revokeDevice(_ payload: BetterAuthRevokeDeviceSessionRequest) async {
        await store.revokeDeviceSession(payload)
    }

    public func revoke(token: String) async {
        await store.revokeSession(token: token)
    }

    public func revokeAll() async {
        await store.revokeSessions()
    }

    public func revokeOthers() async {
        await store.revokeOtherSessions()
    }

    public func jwt() async throws -> BetterAuthJWT {
        try await store.getSessionJWT()
    }

    public func jwks() async throws -> BetterAuthJWKS {
        try await store.getJWKS()
    }
}
