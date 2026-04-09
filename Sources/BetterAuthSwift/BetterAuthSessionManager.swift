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
    private let eventEmitter: AuthEventEmitter
    private var current: BetterAuthSession?
    private var inFlightRefreshTask: Task<BetterAuthSession, Error>?
    private var autoRefreshTask: Task<Void, Never>?

    public init(configuration: BetterAuthConfiguration,
                sessionStore: BetterAuthSessionStore,
                transport: BetterAuthTransport,
                logger: BetterAuthLogger? = nil,
                eventEmitter: AuthEventEmitter = AuthEventEmitter())
    {
        self.configuration = configuration
        self.sessionStore = sessionStore
        self.network = AuthNetworkClient(baseURL: configuration.baseURL,
                                         transport: transport,
                                         retryPolicy: configuration.retryPolicy,
                                         requestOrigin: configuration.requestOrigin)
        self.logger = logger
        self.eventEmitter = eventEmitter
    }

    // MARK: - Event Stream

    public nonisolated var onAuthStateChange: AuthEventEmitter {
        eventEmitter
    }

    // MARK: - Session Access

    /// Loads the persisted session from the session store without entering the actor.
    public nonisolated func loadStoredSession() throws -> BetterAuthSession? {
        try sessionStore.loadSession(for: configuration.storage.key)
    }

    /// Restores the session from storage into memory and starts auto-refresh if configured.
    public func restoreSession() throws -> BetterAuthSession? {
        let session = try loadStoredSession()
        try applyRestoredSession(session)
        return session
    }

    /// Restores the best available session for app launch and reports how it was recovered.
    public func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        let source: BetterAuthRestoreSource
        if current != nil {
            source = .memory
        } else {
            do {
                _ = try restoreSession()
            } catch {
                try clearSession(event: .signedOut)
                return .cleared(.storageFailure)
            }
            source = .keychain
        }

        guard let current else { return .noStoredSession }
        guard current.needsRefresh(clockSkew: configuration.clockSkew) else {
            return .restored(current, source: source, refresh: .notNeeded)
        }

        do {
            let refreshed = try await refreshSession()
            return .restored(refreshed, source: source, refresh: .refreshed)
        } catch {
            if shouldClearSession(for: error) {
                return .cleared(clearReason(for: error))
            }
            return .restored(current, source: source, refresh: .deferred)
        }
    }

    /// Returns the current in-memory session, if any.
    public func currentSession() -> BetterAuthSession? {
        current
    }

    public func applyRestoredSession(_ session: BetterAuthSession?) throws {
        current = session
        logger?.debug("Session restored: \(session != nil ? "found" : "none")")
        eventEmitter.emit(.initialSession, session: session)
        if configuration.autoRefreshToken {
            if session != nil {
                startAutoRefresh()
            } else {
                stopAutoRefresh()
            }
        }
    }

    public func updateSession(_ session: BetterAuthSession?) throws {
        current = session
        if let session {
            try sessionStore.saveSession(session, for: configuration.storage.key)
        } else {
            try sessionStore.clearSession(for: configuration.storage.key)
        }
    }

    // MARK: - Email + Password

    @discardableResult
    public func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        let result: EmailSignUpResult = try await network.post(path: configuration.endpoints.emailSignUpPath,
                                                               body: payload, accessToken: nil)
        if case let .signedIn(session) = result {
            try setSession(session, event: .signedIn)
        }
        return result
    }

    @discardableResult
    public func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await network.post(path: configuration.endpoints.emailSignInPath,
                                                                body: payload, accessToken: nil)
        try setSession(session, event: .signedIn)
        return session
    }

    // MARK: - Username

    public func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        let response: UsernameAvailabilityResponse = try await network
            .post(path: configuration.endpoints.usernameAvailabilityPath,
                  body: payload, accessToken: nil)
        return response.available
    }

    @discardableResult
    public func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await network.post(path: configuration.endpoints.usernameSignInPath,
                                                                body: payload, accessToken: nil)
        try setSession(session, event: .signedIn)
        return session
    }

    // MARK: - Apple

    @discardableResult
    public func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await network.post(path: configuration.endpoints.nativeAppleSignInPath,
                                                                body: payload,
                                                                accessToken: nil)
        try setSession(session, event: .signedIn)
        return session
    }

    // MARK: - Social

    @discardableResult
    public func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        let response: SocialSignInTransportResponse = try await network
            .post(path: configuration.endpoints.socialSignInPath,
                  body: payload, accessToken: nil)

        if let session = response.materializedSession {
            try setSession(session, event: .signedIn)
            let signedIn = SocialSignInSuccessResponse(redirect: response.redirect,
                                                       token: session.session.accessToken,
                                                       url: response.url,
                                                       user: session.user)
            return .signedIn(signedIn)
        }

        if let signedIn = response.signedIn {
            let session = try await materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try setSession(session, event: .signedIn)
            return .signedIn(signedIn)
        }

        switch response.authorizationURL {
        case let .success(authorizationURL):
            return .authorizationURL(authorizationURL)

        case let .failure(error):
            throw error
        }
    }

    // MARK: - Anonymous

    @discardableResult
    public func signInAnonymously() async throws -> BetterAuthSession {
        let response: SignedInTokenResponse = try await network.post(path: configuration.endpoints.anonymousSignInPath,
                                                                     accessToken: nil)
        let session = try await materializeSession(token: response.token, fallbackUser: response.user)
        try setSession(session, event: .signedIn)
        return session
    }

    @discardableResult
    public func deleteAnonymousUser() async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.deleteAnonymousUserPath,
                  accessToken: current?.session.accessToken)
        try setSession(nil, event: .signedOut)
        return response.status
    }

    // MARK: - Delete User

    @discardableResult
    public func deleteUser(_ payload: DeleteUserRequest = .init()) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.deleteUserPath,
                  body: payload,
                  accessToken: current?.session.accessToken)
        try setSession(nil, event: .signedOut)
        return response.status
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    public func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        guard current != nil else { throw BetterAuthError.missingSession }
        return try await signUpWithEmail(payload)
    }

    @discardableResult
    public func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        guard current != nil else { throw BetterAuthError.missingSession }
        return try await signInWithApple(payload)
    }

    @discardableResult
    public func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        guard current != nil else { throw BetterAuthError.missingSession }
        return try await signInWithSocial(payload)
    }

    // MARK: - Re-authentication

    @discardableResult
    public func reauthenticate(password: String) async throws -> Bool {
        guard let currentUser = current else { throw BetterAuthError.missingSession }
        guard let email = currentUser.user.email else { throw BetterAuthError.missingSession }
        let verificationSession: BetterAuthSession = try await network
            .post(path: configuration.endpoints.emailSignInPath,
                  body: EmailSignInRequest(email: email, password: password),
                  accessToken: nil)
        guard verificationSession.user.id == currentUser.user.id else {
            throw BetterAuthError.invalidResponse
        }
        // Revoke the ephemeral verification session to avoid orphaned server-side sessions.
        do {
            let _: BetterAuthStatusResponse = try await network.post(
                path: configuration.endpoints.revokeSessionPath,
                body: RevokeSessionRequest(token: verificationSession.session.id),
                accessToken: verificationSession.session.accessToken
            )
        } catch {
            // Best-effort cleanup; credential verification already succeeded.
        }
        return true
    }

    // MARK: - Generic OAuth

    public func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await network.post(path: configuration.endpoints.genericOAuthSignInPath, body: payload, accessToken: nil)
    }

    public func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await network.post(path: configuration.endpoints.genericOAuthLinkPath, body: payload,
                               accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await network.get(path: oauthCallbackPath(for: payload),
                                                               accessToken: current?.session.accessToken)
        try setSession(session, event: .signedIn)
        return session
    }

    // MARK: - Password Reset

    @discardableResult
    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.forgotPasswordPath,
                  body: payload, accessToken: nil)
        return response.status
    }

    @discardableResult
    public func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network.post(path: configuration.endpoints.resetPasswordPath,
                                                                        body: payload, accessToken: nil)
        return response.status
    }

    // MARK: - Email Verification

    @discardableResult
    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.sendVerificationEmailPath,
                  body: payload,
                  accessToken: current?.session.accessToken)
        return response.status
    }

    @discardableResult
    public func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        let result: VerifyEmailResult = try await network.get(path: configuration.endpoints.verifyEmailPath,
                                                              queryItems: [URLQueryItem(name: "token",
                                                                                        value: payload.token)],
                                                              accessToken: nil)
        if case let .signedIn(session) = result {
            try setSession(session, event: .signedIn)
        }
        return result
    }

    @discardableResult
    public func changeEmail(_ payload: ChangeEmailRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network.post(path: configuration.endpoints.changeEmailPath,
                                                                        body: payload,
                                                                        accessToken: current?.session.accessToken)
        return response.status
    }

    // MARK: - User Management

    @discardableResult
    public func updateUser(_ payload: UpdateUserRequest) async throws -> UpdateUserResponse {
        let response: UpdateUserResponse = try await network.post(path: configuration.endpoints.updateUserPath,
                                                                  body: payload,
                                                                  accessToken: current?.session.accessToken)
        if let user = response.user, let current {
            try setSession(BetterAuthSession(session: current.session, user: current.user.merged(with: user)),
                           event: .userUpdated)
        }
        return response
    }

    @discardableResult
    public func changePassword(_ payload: ChangePasswordRequest) async throws -> ChangePasswordResponse {
        let response: ChangePasswordResponse = try await network.post(path: configuration.endpoints.changePasswordPath,
                                                                      body: payload,
                                                                      accessToken: current?.session.accessToken)
        if payload.revokeOtherSessions == true, let session = response.session {
            try setSession(session, event: .tokenRefreshed)
        } else if payload.revokeOtherSessions == true, let rotatedToken = response.token {
            let materializedSession: BetterAuthSession = try await network
                .get(path: configuration.endpoints.currentSessionPath,
                     accessToken: rotatedToken)
            try setSession(materializedSession, event: .tokenRefreshed)
        } else if let current {
            try setSession(BetterAuthSession(session: current.session, user: current.user.merged(with: response.user)),
                           event: .userUpdated)
        }
        return response
    }

    // MARK: - Session Refresh

    /// Refreshes the current session with the backend. Deduplicates concurrent calls.
    @discardableResult
    public func refreshSession() async throws -> BetterAuthSession {
        if let existing = inFlightRefreshTask {
            logger?.debug("Reusing in-flight refresh task")
            return try await existing.value
        }

        guard let existingSession = current else {
            throw BetterAuthError.missingSession
        }

        let network = self.network
        let endpoints = configuration.endpoints
        let task = Task { () -> BetterAuthSession in
            if let refreshToken = existingSession.session.refreshToken {
                struct RefreshPayload: Encodable, Sendable { let refreshToken: String }
                return try await network.post(path: endpoints.sessionRefreshPath,
                                              body: RefreshPayload(refreshToken: refreshToken),
                                              accessToken: existingSession.session.accessToken)
            } else {
                return try await network.post(path: endpoints.sessionRefreshPath,
                                              accessToken: existingSession.session.accessToken)
            }
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
            if shouldClearSession(for: error) {
                try clearSession(event: .sessionExpired)
            }
            throw error
        }
    }

    @discardableResult
    public func refreshSessionIfNeeded() async throws -> BetterAuthSession {
        guard let current else { throw BetterAuthError.missingSession }
        guard current.needsRefresh(clockSkew: configuration.clockSkew) else { return current }
        return try await refreshSession()
    }

    @discardableResult
    public func fetchCurrentSession() async throws -> BetterAuthSession {
        let existingToken = current?.session.accessToken
        do {
            let session: BetterAuthSession = try await network.get(path: configuration.endpoints.currentSessionPath,
                                                                   accessToken: existingToken)
            try setSession(session, event: .tokenRefreshed)
            return session
        } catch {
            if shouldClearSession(for: error) { try clearSession(event: .sessionExpired) }
            throw error
        }
    }

    // MARK: - Session Management

    public func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await network.get(path: configuration.endpoints.listSessionsPath, accessToken: current?.session.accessToken)
    }

    public func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await network.get(path: configuration.endpoints.listDeviceSessionsPath,
                              accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async throws
        -> BetterAuthSession
    {
        let session: BetterAuthSession = try await network
            .post(path: configuration.endpoints.setActiveDeviceSessionPath,
                  body: payload,
                  accessToken: current?.session.accessToken)
        try setSession(session, event: .signedIn)
        return session
    }

    @discardableResult
    public func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.revokeDeviceSessionPath,
                  body: payload,
                  accessToken: current?.session.accessToken)
        if payload.sessionToken == current?.session.accessToken {
            try setSession(nil, event: .signedOut)
        }
        return response.status
    }

    // MARK: - JWT

    public func getSessionJWT() async throws -> BetterAuthJWT {
        try await network.get(path: configuration.endpoints.sessionJWTPath, accessToken: current?.session.accessToken)
    }

    public func getJWKS() async throws -> BetterAuthJWKS {
        try await network.get(path: configuration.endpoints.jwksPath, accessToken: nil)
    }

    // MARK: - Linked Accounts

    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await network.get(path: configuration.endpoints.listLinkedAccountsPath,
                              accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await network.post(path: configuration.endpoints.linkSocialAccountPath, body: payload,
                               accessToken: current?.session.accessToken)
    }

    // MARK: - Passkeys

    public func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await network.get(path: configuration.endpoints.passkeyRegisterOptionsPath,
                              queryItems: [URLQueryItem(name: "name", value: request.name),
                                           URLQueryItem(name: "authenticatorAttachment",
                                                        value: request.authenticatorAttachment)],
                              accessToken: current?.session.accessToken)
    }

    public func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await network.get(path: configuration.endpoints.passkeyAuthenticateOptionsPath,
                              accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func registerPasskey(_ payload: PasskeyRegistrationRequest) async throws -> Passkey {
        try await network.post(path: configuration.endpoints.passkeyRegisterPath, body: payload,
                               accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await network
            .post(path: configuration.endpoints.passkeyAuthenticatePath,
                  body: payload, accessToken: nil)
        if let session = response.materializedSession {
            try setSession(session, event: .signedIn)
            return session
        }
        if let signedIn = response.signedIn {
            let session = try await materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try setSession(session, event: .signedIn)
            return session
        }
        throw BetterAuthError.invalidResponse
    }

    public func listPasskeys() async throws -> [Passkey] {
        try await network.get(path: configuration.endpoints.listPasskeysPath, accessToken: current?.session.accessToken)
    }

    public func updatePasskey(_ payload: UpdatePasskeyRequest) async throws -> Passkey {
        let response: UpdatePasskeyResponse = try await network.post(path: configuration.endpoints.updatePasskeyPath,
                                                                     body: payload,
                                                                     accessToken: current?.session.accessToken)
        return response.passkey
    }

    @discardableResult
    public func deletePasskey(_ payload: DeletePasskeyRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network.post(path: configuration.endpoints.deletePasskeyPath,
                                                                        body: payload,
                                                                        accessToken: current?.session.accessToken)
        return response.status
    }

    // MARK: - Magic Link

    @discardableResult
    public func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.magicLinkSignInPath,
                  body: payload, accessToken: nil)
        return response.status
    }

    @discardableResult
    public func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        let result: MagicLinkVerificationResult = try await network
            .get(path: configuration.endpoints.magicLinkVerifyPath,
                 queryItems: [URLQueryItem(name: "token",
                                           value: payload.token),
                              URLQueryItem(name: "callbackURL",
                                           value: payload
                                               .callbackURL),
                              URLQueryItem(name: "newUserCallbackURL",
                                           value: payload
                                               .newUserCallbackURL),
                              URLQueryItem(name: "errorCallbackURL",
                                           value: payload
                                               .errorCallbackURL)],
                 accessToken: nil)
        if case let .signedIn(session) = result {
            try setSession(session, event: .signedIn)
        }
        return result
    }

    // MARK: - Email OTP

    @discardableResult
    public func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        let response: EmailOTPRequestResponse = try await network
            .post(path: configuration.endpoints.emailOTPRequestPath,
                  body: payload, accessToken: nil)
        return response.success
    }

    @discardableResult
    public func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await network
            .post(path: configuration.endpoints.emailOTPSignInPath,
                  body: payload, accessToken: nil)
        if let session = response.materializedSession {
            try setSession(session, event: .signedIn)
            return session
        }
        if let signedIn = response.signedIn {
            let session = try await materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try setSession(session, event: .signedIn)
            return session
        }
        throw BetterAuthError.invalidResponse
    }

    @discardableResult
    public func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        let result: EmailOTPVerifyResult = try await network.post(path: configuration.endpoints.emailOTPVerifyPath,
                                                                  body: payload, accessToken: nil)
        if case let .signedIn(session) = result {
            try setSession(session, event: .signedIn)
        } else if case let .verified(user) = result, let current, current.user.id == user.id {
            try setSession(BetterAuthSession(session: current.session, user: current.user.merged(with: user)),
                           event: .userUpdated)
        }
        return result
    }

    // MARK: - Phone OTP

    @discardableResult
    public func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        let response: PhoneOTPRequestResponse = try await network
            .post(path: configuration.endpoints.phoneOTPRequestPath,
                  body: payload, accessToken: nil)
        return response.message == "code sent"
    }

    @discardableResult
    public func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async throws -> PhoneOTPVerifyResponse {
        let accessToken = payload.updatePhoneNumber == true ? current?.session.accessToken : nil
        let response: PhoneOTPVerifyResponse = try await network.post(path: configuration.endpoints.phoneOTPVerifyPath,
                                                                      body: payload, accessToken: accessToken)
        if let token = response.token, let user = response.user {
            let twoFactorUser = TwoFactorUser(id: user.id, email: user.email, name: user.name,
                                              username: user.username, displayUsername: user.displayUsername,
                                              twoFactorEnabled: false)
            let session = try await materializeSession(token: token, fallbackUser: twoFactorUser)
            try setSession(session, event: .signedIn)
        } else if let user = response.user, let current, current.user.id == user.id {
            try setSession(BetterAuthSession(session: current.session, user: current.user.merged(with: user)),
                           event: .userUpdated)
        }
        return response
    }

    @discardableResult
    public func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await network
            .post(path: configuration.endpoints.phoneOTPSignInPath,
                  body: payload, accessToken: nil)
        let session = try await materializeSession(token: response.token, fallbackUser: response.user)
        try setSession(session, event: .signedIn)
        return session
    }

    // MARK: - Two Factor

    public func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await network.post(path: configuration.endpoints.twoFactorEnablePath, body: payload,
                               accessToken: current?.session.accessToken)
    }

    @discardableResult
    public func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await network
            .post(path: configuration.endpoints.twoFactorVerifyTOTPPath,
                  body: payload, accessToken: nil)
        let session = try await materializeSession(token: response.token, fallbackUser: response.user)
        try setSession(session, event: .signedIn)
        return session
    }

    @discardableResult
    public func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        let response: TwoFactorChallengeStatusResponse = try await network
            .post(path: configuration.endpoints.twoFactorSendOTPPath,
                  body: payload, accessToken: nil)
        return response.status
    }

    @discardableResult
    public func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await network
            .post(path: configuration.endpoints.twoFactorVerifyOTPPath,
                  body: payload, accessToken: nil)
        let session = try await materializeSession(token: response.token, fallbackUser: response.user)
        try setSession(session, event: .signedIn)
        return session
    }

    @discardableResult
    public func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws
        -> BetterAuthSession
    {
        let response: TwoFactorSessionResponse = try await network
            .post(path: configuration.endpoints.twoFactorVerifyBackupCodePath,
                  body: payload, accessToken: nil)
        let session = try await materializeSession(token: response.token, fallbackUser: response.user)
        try setSession(session, event: .signedIn)
        return session
    }

    @discardableResult
    public func disableTwoFactor(_ payload: TwoFactorDisableRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.twoFactorDisablePath,
                  body: payload,
                  accessToken: current?.session.accessToken)
        return response.status
    }

    public func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        struct Request: Encodable, Sendable { let password: String }
        let response: TwoFactorGenerateBackupCodesResponse = try await network
            .post(path: configuration.endpoints.twoFactorGenerateBackupCodesPath,
                  body: Request(password: password),
                  accessToken: current?.session
                      .accessToken)
        return response.backupCodes
    }

    // MARK: - Session Revocation

    @discardableResult
    public func revokeSession(token: String) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network.post(path: configuration.endpoints.revokeSessionPath,
                                                                        body: RevokeSessionRequest(token: token),
                                                                        accessToken: current?.session.accessToken)
        if token == current?.session.accessToken {
            try setSession(nil, event: .signedOut)
        }
        return response.status
    }

    @discardableResult
    public func revokeSessions() async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.revokeSessionsPath,
                  accessToken: current?.session.accessToken)
        try setSession(nil, event: .signedOut)
        return response.status
    }

    @discardableResult
    public func revokeOtherSessions() async throws -> Bool {
        let response: BetterAuthStatusResponse = try await network
            .post(path: configuration.endpoints.revokeOtherSessionsPath,
                  accessToken: current?.session.accessToken)
        return response.status
    }

    // MARK: - Restore / Refresh

    /// Restores from storage and refreshes if expired. The recommended way to bootstrap a session at app launch.
    public func restoreOrRefreshSession() async throws -> BetterAuthSession? {
        if current == nil {
            do { _ = try restoreSession() } catch {
                try clearSession(event: .signedOut)
                throw error
            }
        }
        guard let current else { return nil }
        if current.needsRefresh(clockSkew: configuration.clockSkew) {
            do { return try await refreshSession() } catch {
                if shouldClearSession(for: error) { try clearSession(event: .sessionExpired) }
                throw error
            }
        }
        return current
    }

    // MARK: - Authorized Request

    public func authorizedRequest(path: String, method: String = "GET") async throws -> URLRequest {
        let session = try await validSession()
        guard let url = URL(string: path, relativeTo: configuration.baseURL) else {
            throw BetterAuthError.invalidURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(session.session.accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    // MARK: - Sign Out

    /// Signs out and clears the local session. Optionally revokes the session on the backend.
    public func signOut(remotely: Bool = true) async throws {
        stopAutoRefresh()
        if remotely, current != nil {
            _ = try await network.post(path: configuration.endpoints.signOutPath,
                                       accessToken: current?.session.accessToken) as SignOutResponse
        }
        try setSession(nil, event: .signedOut)
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

    private func autoRefreshTick() async {
        guard let expiresAt = current?.session.expiresAt else { return }
        let ticksUntilExpiry = Int(expiresAt.timeIntervalSinceNow / AutoRefreshConstants.tickInterval)
        if ticksUntilExpiry <= AutoRefreshConstants.tickThreshold {
            logger?.debug("Auto-refreshing session (\(ticksUntilExpiry) ticks until expiry)")
            _ = try? await refreshSession()
        }
    }

    // MARK: - Deep Link Handling

    public func parseIncomingURL(_ url: URL) -> BetterAuthIncomingURL {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            return .unsupported
        }

        let path = components.path
        let queryItems = components.queryItems ?? []

        if let code = queryItems.first(where: { $0.name == "code" })?.value,
           let state = queryItems.first(where: { $0.name == "state" })?.value
        {
            let pathComponents = path.split(separator: "/")
            if let callbackIndex = pathComponents.firstIndex(of: "callback"), callbackIndex + 1 < pathComponents.count {
                let providerId = String(pathComponents[callbackIndex + 1])
                let issuer = queryItems.first(where: { $0.name == "iss" })?.value
                return .genericOAuth(.init(providerId: providerId, code: code, state: state, issuer: issuer))
            }
        }

        if path.hasSuffix(configuration.endpoints.magicLinkVerifyPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .magicLink(.init(token: token,
                                    callbackURL: queryItems.first(where: { $0.name == "callbackURL" })?.value,
                                    newUserCallbackURL: queryItems.first(where: { $0.name == "newUserCallbackURL" })?
                                        .value,
                                    errorCallbackURL: queryItems.first(where: { $0.name == "errorCallbackURL" })?
                                        .value))
        }

        if path.hasSuffix(configuration.endpoints.verifyEmailPath),
           let token = queryItems.first(where: { $0.name == "token" })?.value
        {
            return .verifyEmail(.init(token: token))
        }

        return .unsupported
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

    // MARK: - Session Lifecycle Helpers

    private func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent) throws {
        try updateSession(session)
        eventEmitter.emit(event, session: session)
        if session != nil, configuration.autoRefreshToken {
            startAutoRefresh()
        } else if session == nil {
            stopAutoRefresh()
        }
    }

    private func clearSession(event: AuthChangeEvent = .signedOut) throws {
        try setSession(nil, event: event)
    }

    private func shouldClearSession(for error: Error) -> Bool {
        guard let authError = error as? BetterAuthError else { return false }
        if authError.isUnauthorized { return true }
        if let code = authError.authErrorCode, ErrorParsing.sessionCleanupCodes.contains(code) { return true }
        return false
    }

    private func clearReason(for error: Error) -> BetterAuthRestoreClearReason {
        guard let authError = error as? BetterAuthError else { return .unauthorized }
        switch authError.authErrorCode {
        case .sessionExpired:
            return .sessionExpired

        case .sessionNotFound:
            return .invalidSession

        case .refreshTokenExpired:
            return .refreshTokenExpired

        case .invalidRefreshToken:
            return .invalidRefreshToken

        default:
            return authError.isUnauthorized ? .unauthorized : .storageFailure
        }
    }

    private func validSession() async throws -> BetterAuthSession {
        if let current, current.needsRefresh(clockSkew: configuration.clockSkew) {
            return try await refreshSession()
        }
        if let current { return current }
        throw BetterAuthError.missingSession
    }

    // MARK: - Session Materialization (DRY: single path for token-based flows)

    private func materializeSession(token: String, fallbackUser: TwoFactorUser) async throws -> BetterAuthSession {
        let previous = current
        let session: BetterAuthSession = try await network.get(path: configuration.endpoints.currentSessionPath,
                                                               accessToken: token)
        guard session.user.id == fallbackUser.id else {
            return previous ?? session
        }
        return BetterAuthSession(session: session.session,
                                 user: .init(id: session.user.id,
                                             email: session.user.email ?? fallbackUser.email,
                                             name: session.user.name ?? fallbackUser.name,
                                             username: session.user.username ?? fallbackUser.username,
                                             displayUsername: session.user.displayUsername ?? fallbackUser
                                                 .displayUsername))
    }

    private func materializeSession(token: String,
                                    fallbackUser: BetterAuthSession.User) async throws -> BetterAuthSession
    {
        let previous = current
        let session: BetterAuthSession = try await network.get(path: configuration.endpoints.currentSessionPath,
                                                               accessToken: token)
        guard session.user.id == fallbackUser.id else {
            return previous ?? session
        }
        return BetterAuthSession(session: session.session,
                                 user: session.user.merged(with: fallbackUser))
    }

    // MARK: - Phone Verification Result Handling

    // MARK: - OAuth URL Construction

    private func oauthCallbackPath(for payload: GenericOAuthCallbackRequest) -> String {
        var components = URLComponents()
        components.path = "/api/auth/oauth2/callback/\(payload.providerId)"
        components.queryItems = [URLQueryItem(name: "code", value: payload.code),
                                 URLQueryItem(name: "state", value: payload.state)]
        if let issuer = payload.issuer {
            components.queryItems?.append(URLQueryItem(name: "iss", value: issuer))
        }
        return components.string ?? "/api/auth/oauth2/callback/\(payload.providerId)"
    }
}

private struct SignOutResponse: Decodable {
    let success: Bool
}

private struct RevokeSessionRequest: Encodable {
    let token: String
}
