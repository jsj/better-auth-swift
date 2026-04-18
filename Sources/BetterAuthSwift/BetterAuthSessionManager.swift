import Foundation

private enum AutoRefreshConstants {
    static let tickInterval: TimeInterval = 30
    static let tickThreshold = 3
}

/// Actor-isolated session manager that owns the full auth lifecycle.
///
/// Access via ``BetterAuthClient/auth``. Handles sign-in, sign-out,
/// session persistence, automatic token refresh, and event emission.
public actor BetterAuthSessionManager {
    private let configuration: BetterAuthConfiguration
    private let sessionStore: BetterAuthSessionStore
    private let network: AuthNetworkClient
    private let logger: BetterAuthLogger?
    private let state: BetterAuthSessionState
    private let sessionService: BetterAuthSessionService
    private let refreshService: BetterAuthSessionRefreshService
    private let authFlowService: BetterAuthAuthFlowService
    private let userAccountService: BetterAuthUserAccountService
    private let callbackHandler: BetterAuthCallbackHandler
    private var authStateListeners: [any BetterAuthAuthStateListener] = []
    private var inFlightRefreshTask: Task<BetterAuthSession, Error>?
    private var autoRefreshTask: Task<Void, Never>?

    private var context: BetterAuthSessionContext {
        BetterAuthSessionContext(configuration: configuration,
                                 state: state,
                                 sessionService: sessionService,
                                 refreshService: refreshService,
                                 authFlowService: authFlowService,
                                 userAccountService: userAccountService,
                                 callbackHandler: callbackHandler,
                                 network: network,
                                 logger: logger)
    }

    private func makeRelay() -> BetterAuthSessionEventRelay {
        BetterAuthSessionEventRelay(context: context,
                                    refreshSession: {
                                        try await self.refreshSession()
                                    })
    }

    public init(configuration: BetterAuthConfiguration,
                sessionStore: BetterAuthSessionStore,
                transport: BetterAuthTransport,
                logger: BetterAuthLogger? = nil,
                eventEmitter: AuthEventEmitter = AuthEventEmitter(),
                authStateListeners: [any BetterAuthAuthStateListener] = [])
    {
        self.configuration = configuration
        self.sessionStore = sessionStore
        self.network = AuthNetworkClient(baseURL: configuration.baseURL,
                                         transport: transport,
                                         retryPolicy: configuration.retryPolicy,
                                         requestOrigin: configuration.requestOrigin)
        self.logger = logger
        self.state = BetterAuthSessionState(eventEmitter: eventEmitter)
        self.sessionService = BetterAuthSessionService(configuration: configuration, sessionStore: sessionStore)
        self.refreshService = BetterAuthSessionRefreshService(configuration: configuration, network: self.network)
        self.authFlowService = BetterAuthAuthFlowService(configuration: configuration, network: self.network)
        self.userAccountService = BetterAuthUserAccountService(configuration: configuration, network: self.network)
        self.callbackHandler = BetterAuthCallbackHandler(endpoints: configuration.endpoints)
        self.authStateListeners = authStateListeners
    }

    // MARK: - Event Stream

    public nonisolated var onAuthStateChange: AuthEventEmitter {
        state.eventEmitter
    }

    public nonisolated var authStateChanges: AsyncStream<AuthStateChange> {
        state.stateChanges
    }

    public nonisolated var currentAuthState: AuthStateChange? {
        state.latest
    }

    // MARK: - Session Access

    /// Loads the persisted session from the session store without entering the actor.
    public nonisolated func loadStoredSession() throws -> BetterAuthSession? {
        try sessionService.loadStoredSession()
    }

    /// Restores the session from storage into memory and starts auto-refresh if configured.
    public func restoreSession() throws -> BetterAuthSession? {
        try BetterAuthSessionBootstrapService(context: context, relay: makeRelay()).restoreSession()
    }

    /// Restores the best available session for app launch and reports how it was recovered.
    public func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        try await BetterAuthSessionBootstrapService(context: context, relay: makeRelay())
            .restoreSessionOnLaunch(refreshSession: { try await self.refreshSession() })
    }

    /// Returns the current in-memory session, if any.
    public func currentSession() -> BetterAuthSession? {
        state.currentSession
    }

    public func applyRestoredSession(_ session: BetterAuthSession?) throws {
        try BetterAuthSessionBootstrapService(context: context, relay: makeRelay()).applyRestoredSession(session)
        if configuration.autoRefreshToken {
            if session != nil {
                startAutoRefresh()
            } else {
                stopAutoRefresh()
            }
        }
    }

    public func updateSession(_ session: BetterAuthSession?) throws {
        state.replaceCurrentSession(session)
        try sessionService.persist(session)
    }

    // MARK: - Email + Password

    @discardableResult
    public func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signUpWithEmail(payload)
    }

    @discardableResult
    public func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithEmail(payload)
    }

    // MARK: - Username

    public func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .isUsernameAvailable(payload)
    }

    @discardableResult
    public func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithUsername(payload)
    }

    // MARK: - Apple

    @discardableResult
    public func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithApple(payload)
    }

    // MARK: - Social

    @discardableResult
    public func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithSocial(payload)
    }

    // MARK: - Anonymous

    @discardableResult
    public func signInAnonymously() async throws -> BetterAuthSession {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInAnonymously()
    }

    @discardableResult
    public func deleteAnonymousUser() async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .deleteAnonymousUser(accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Delete User

    @discardableResult
    public func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .deleteUser(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    public func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signUpWithEmail(payload)
    }

    @discardableResult
    public func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signInWithApple(payload)
    }

    @discardableResult
    public func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        guard state.currentSession != nil else { throw BetterAuthError.missingSession }
        return try await signInWithSocial(payload)
    }

    // MARK: - Re-authentication

    @discardableResult
    public func reauthenticate(password: String) async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .reauthenticate(password: password, currentSession: state.currentSession)
    }

    // MARK: - Generic OAuth

    public func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await BetterAuthOAuthService(context: context, relay: makeRelay())
            .beginGenericOAuth(payload)
    }

    public func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await BetterAuthOAuthService(context: context, relay: makeRelay())
            .linkGenericOAuth(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        try await BetterAuthOAuthService(context: context, relay: makeRelay())
            .completeGenericOAuth(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Password Reset

    @discardableResult
    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .requestPasswordReset(payload)
    }

    @discardableResult
    public func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        try await BetterAuthPrimaryAuthService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .resetPassword(payload)
    }

    // MARK: - Email Verification

    @discardableResult
    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .sendVerificationEmail(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .verifyEmail(payload)
    }

    @discardableResult
    public func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .changeEmail(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - User Management

    @discardableResult
    public func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .updateUser(payload, currentSession: state.currentSession)
    }

    @discardableResult
    public func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .changePassword(payload, currentSession: state.currentSession)
    }

    // MARK: - Session Refresh

    /// Refreshes the current session with the backend. Deduplicates concurrent calls.
    @discardableResult
    public func refreshSession() async throws -> BetterAuthSession {
        if let existing = inFlightRefreshTask {
            logger?.debug("Reusing in-flight refresh task")
            return try await existing.value
        }

        guard let existingSession = state.currentSession else {
            throw BetterAuthError.missingSession
        }

        // Keep the refresh task scoped to immutable snapshots so the unstructured
        // task does not capture actor-isolated mutable state.
        let task = Task { () -> BetterAuthSession in
            try await refreshService.refresh(using: existingSession)
        }

        inFlightRefreshTask = task
        do {
            let session = try await task.value
            inFlightRefreshTask = nil
            try setSession(session, event: .tokenRefreshed)
            logger?.info("Session refreshed")
            return session
        } catch {
            inFlightRefreshTask = nil
            if makeRelay().shouldClearSession(for: error) {
                try clearSession(event: .sessionExpired)
            }
            throw error
        }
    }

    @discardableResult
    public func refreshSessionIfNeeded() async throws -> BetterAuthSession {
        guard let current = state.currentSession else { throw BetterAuthError.missingSession }
        guard current.needsRefresh(clockSkew: configuration.auth.clockSkew) else { return current }
        return try await refreshSession()
    }

    @discardableResult
    public func fetchCurrentSession() async throws -> BetterAuthSession {
        try await BetterAuthSessionBootstrapService(context: context, relay: makeRelay()).fetchCurrentSession()
    }

    // MARK: - Session Management

    public func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .listSessions(accessToken: state.currentSession?.session.accessToken)
    }

    public func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .listDeviceSessions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .setActiveDeviceSession(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .revokeDeviceSession(payload,
                                 accessToken: state.currentSession?.session.accessToken,
                                 currentAccessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - JWT

    public func getSessionJWT() async throws -> BetterAuthJWT {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .getSessionJWT(accessToken: state.currentSession?.session.accessToken)
    }

    public func getJWKS() async throws -> BetterAuthJWKS {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay()).getJWKS()
    }

    // MARK: - Linked Accounts

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .listLinkedAccounts(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await BetterAuthProfileService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .linkSocialAccount(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Passkeys

    public func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .passkeyRegistrationOptions(request, accessToken: state.currentSession?.session.accessToken)
    }

    public func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .passkeyAuthenticateOptions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .registerPasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .authenticateWithPasskey(payload)
    }

    public func listPasskeys() async throws -> [Passkey] {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .listPasskeys(accessToken: state.currentSession?.session.accessToken)
    }

    public func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .updatePasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool {
        try await BetterAuthPasskeyService(context: context,
                                           relay: makeRelay(),
                                           materializer: BetterAuthSessionMaterializer(context: context))
            .deletePasskey(payload, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Magic Link

    @discardableResult
    public func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .requestMagicLink(payload)
    }

    @discardableResult
    public func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .verifyMagicLink(payload)
    }

    // MARK: - Email OTP

    @discardableResult
    public func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .requestEmailOTP(payload)
    }

    @discardableResult
    public func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithEmailOTP(payload)
    }

    @discardableResult
    public func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .verifyEmailOTP(payload, currentSession: state.currentSession)
    }

    // MARK: - Phone OTP

    @discardableResult
    public func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .requestPhoneOTP(payload)
    }

    @discardableResult
    public func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .verifyPhoneNumber(payload,
                               accessToken: payload.updatePhoneNumber == true ? state.currentSession?.session.accessToken : nil,
                               currentSession: state.currentSession)
    }

    @discardableResult
    public func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await BetterAuthOneTimeCodeService(context: context,
                                               relay: makeRelay(),
                                               materializer: BetterAuthSessionMaterializer(context: context))
            .signInWithPhoneOTP(payload)
    }

    // MARK: - Two Factor

    public func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .enableTwoFactor(payload, accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .verifyTwoFactorTOTP(payload)
    }

    @discardableResult
    public func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .sendTwoFactorOTP(payload)
    }

    @discardableResult
    public func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .verifyTwoFactorOTP(payload)
    }

    @discardableResult
    public func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws
        -> BetterAuthSession
    {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .verifyTwoFactorRecoveryCode(payload)
    }

    @discardableResult
    public func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .disableTwoFactor(payload, accessToken: state.currentSession?.session.accessToken)
    }

    public func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await BetterAuthTwoFactorService(context: context,
                                             relay: makeRelay(),
                                             materializer: BetterAuthSessionMaterializer(context: context))
            .generateTwoFactorRecoveryCodes(password: password,
                                            accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Session Revocation

    @discardableResult
    public func revokeSession(token: String) async throws -> Bool {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .revokeSession(token: token,
                           accessToken: state.currentSession?.session.accessToken,
                           currentAccessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func revokeSessions() async throws -> Bool {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .revokeSessions(accessToken: state.currentSession?.session.accessToken)
    }

    @discardableResult
    public func revokeOtherSessions() async throws -> Bool {
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .revokeOtherSessions(accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Restore / Refresh

    /// Restores from storage and refreshes if expired. The recommended way to bootstrap a session at app launch.
    public func restoreOrRefreshSession() async throws -> BetterAuthSession? {
        let bootstrap = BetterAuthSessionBootstrapService(context: context, relay: makeRelay())
        return try await bootstrap
            .restoreOrRefreshSession(restoreSession: { try bootstrap.restoreSession() },
                                     refreshSession: { try await self.refreshSession() })
    }

    // MARK: - Authorized Request

    public func authorizedRequest(path: String, method: String = "GET") async throws -> URLRequest {
        let session = try await makeRelay().validSession()
        let url = try BetterAuthURLResolver.resolve(path, relativeTo: configuration.baseURL)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(session.session.accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    // MARK: - Sign Out

    /// Signs out and clears the local session. Optionally revokes the session on the backend.
    public func signOut(remotely: Bool = true) async throws {
        stopAutoRefresh()
        try await BetterAuthSessionAdministrationService(context: context, relay: makeRelay())
            .signOut(remotely: remotely, accessToken: state.currentSession?.session.accessToken)
    }

    // MARK: - Auto-Refresh

    public func startAutoRefresh() {
        stopAutoRefresh()
        logger?.debug("Starting auto-refresh timer")
        autoRefreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(AutoRefreshConstants.tickInterval))
                guard !Task.isCancelled else { return }
                await self?.autoRefreshTick()
            }
        }
    }

    public func stopAutoRefresh() {
        autoRefreshTask?.cancel()
        autoRefreshTask = nil
    }

    deinit {
        autoRefreshTask?.cancel()
        inFlightRefreshTask?.cancel()
    }

    private func autoRefreshTick() async {
        guard let expiresAt = state.currentSession?.session.expiresAt else { return }
        let ticksUntilExpiry = Int(expiresAt.timeIntervalSinceNow / AutoRefreshConstants.tickInterval)
        if ticksUntilExpiry <= AutoRefreshConstants.tickThreshold {
            logger?.debug("Auto-refreshing session (\(ticksUntilExpiry) ticks until expiry)")
            _ = try? await refreshSession()
        }
    }

    // MARK: - Deep Link Handling

    public func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        callbackHandler.parseIncomingURL(url)
    }

    public func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        switch parseIncomingURL(url) {
        case let .genericOAuth(payload):
            try await .genericOAuth(completeGenericOAuth(payload))

        case let .magicLink(payload):
            try await .magicLink(verifyMagicLink(payload))

        case let .verifyEmail(payload):
            try await .verifyEmail(verifyEmail(payload))

        case .unsupported:
            .ignored
        }
    }

    public func handle(_ url: URL) async {
        do {
            let result = try await handleIncomingURL(url)
            switch result {
            case let .genericOAuth(session):
                logger?.info("OAuth callback handled for session: \(session.session.id)")

            case let .magicLink(result):
                logger?.info("Magic link callback handled: \(result)")

            case let .verifyEmail(result):
                logger?.info("Verify email callback handled: \(result)")

            case .ignored:
                logger?.warning("Unsupported auth callback URL: \(url)")
            }
        } catch {
            logger?.error("Auth callback failed: \(error)")
        }
    }

    public func installAuthStateListeners(_ listeners: [any BetterAuthAuthStateListener]) {
        authStateListeners = listeners
    }

    // MARK: - Session Lifecycle Helpers

    private func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent) throws {
        try makeRelay().setSession(session, event: event)
        let change = AuthStateChange(event: event,
                                     session: session,
                                     transition: makeRelay().transition(for: event, session: session))
        notifyAuthStateListeners(of: change)
        if session != nil, configuration.autoRefreshToken {
            startAutoRefresh()
        } else if session == nil {
            stopAutoRefresh()
        }
    }

    private func clearSession(event: AuthChangeEvent = .signedOut) throws {
        try setSession(nil, event: event)
    }

    private func notifyAuthStateListeners(of change: AuthStateChange) {
        let listeners = authStateListeners
        guard !listeners.isEmpty else { return }
        Task {
            for listener in listeners {
                await listener.authStateDidChange(change)
            }
        }
    }

}

struct SignOutResponse: Decodable {
    let success: Bool
}

struct RevokeSessionRequest: Encodable {
    let token: String
}
