import BetterAuth
import Foundation
import Observation

/// Observable SwiftUI state wrapper around ``BetterAuthClient``.
///
/// Provides `session`, `isLoading`, and `statusMessage` for driving UI,
/// plus async methods that mirror every auth flow on the session manager.
@Observable
@MainActor
public final class AuthStore {
    /// The current authenticated session, or `nil` if signed out.
    public private(set) var session: BetterAuthSession?
    /// Explicit app-launch state for bootstrapping root UI.
    public private(set) var launchState: AuthLaunchState = .idle
    /// The last detailed restore outcome returned by the core SDK.
    public private(set) var lastRestoreResult: BetterAuthRestoreResult?
    /// `true` while any auth operation is in flight.
    public private(set) var isLoading = false
    /// Human-readable status or error message from the last operation.
    public private(set) var statusMessage: String?
    /// Structured error captured from the last failed operation.
    public private(set) var lastError: BetterAuthError?

    private let auth: any BetterAuthAuthPerforming
    private var authStateTask: Task<Void, Never>?

    public init(client: some BetterAuthClientProtocol) {
        auth = client.authLifecycle
        startAuthStateObservation()
    }

    // MARK: - Session

    public func restore() async {
        await bootstrap()
    }

    public func bootstrap() async {
        isLoading = true
        launchState = .restoring
        defer { isLoading = false }
        do {
            let result = try await auth.restoreSessionOnLaunch()
            lastError = nil
            lastRestoreResult = result
            applyRestoreResult(result)
        } catch {
            session = nil
            launchState = .failed
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
        }
    }

    public func refresh() async {
        await perform {
            _ = try await auth.refreshSession()
            statusMessage = "Session refreshed"
        }
    }

    public func fetchCurrentSession() async {
        await perform {
            _ = try await auth.fetchCurrentSession()
            statusMessage = "Session fetched"
        }
    }

    public func signOut(remotely: Bool = true) async {
        await perform {
            try await auth.signOut(remotely: remotely)
            statusMessage = "Signed out"
        }
    }

    // MARK: - Email + Password

    @discardableResult
    public func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing {
            let result = try await auth.signUpWithEmail(payload)
            statusMessage = "Signed up"
            return result
        }
    }

    public func signInWithEmail(_ payload: EmailSignInRequest) async {
        await perform {
            _ = try await auth.signInWithEmail(payload)
            statusMessage = "Signed in"
        }
    }

    public func requestPasswordReset(_ payload: ForgotPasswordRequest) async {
        await perform {
            _ = try await auth.requestPasswordReset(payload)
            statusMessage = "Password reset email sent"
        }
    }

    public func resetPassword(_ payload: ResetPasswordRequest) async {
        await perform {
            _ = try await auth.resetPassword(payload)
            statusMessage = "Password reset"
        }
    }

    public func changePassword(_ payload: ChangePasswordRequest) async {
        await perform {
            _ = try await auth.changePassword(payload)
            statusMessage = "Password changed"
        }
    }

    // MARK: - Username

    @discardableResult
    public func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        try await performThrowing {
            let available = try await auth.isUsernameAvailable(payload)
            statusMessage = available ? "Username available" : "Username taken"
            return available
        }
    }

    public func signInWithUsername(_ payload: UsernameSignInRequest) async {
        await perform {
            _ = try await auth.signInWithUsername(payload)
            statusMessage = "Signed in"
        }
    }

    // MARK: - Apple

    public func signInWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform {
            _ = try await auth.signInWithApple(payload)
            statusMessage = "Signed in with Apple"
        }
    }

    // MARK: - Social / OAuth

    @discardableResult
    public func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing {
            let result = try await auth.signInWithSocial(payload)
            statusMessage = "Social sign-in initiated"
            return result
        }
    }

    @discardableResult
    public func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await auth.beginGenericOAuth(payload)
            statusMessage = "OAuth flow started"
            return response
        }
    }

    @discardableResult
    public func linkGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws
        -> GenericOAuthAuthorizationResponse
    {
        try await performThrowing {
            let response = try await auth.linkGenericOAuth(payload)
            statusMessage = "OAuth link flow started"
            return response
        }
    }

    public func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest) async {
        await perform {
            _ = try await auth.completeGenericOAuth(payload)
            statusMessage = "OAuth completed"
        }
    }

    public func handleIncomingURL(_ url: URL) async {
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

    public func signInAnonymously() async {
        await perform {
            _ = try await auth.signInAnonymously()
            statusMessage = "Signed in anonymously"
        }
    }

    public func deleteAnonymousUser() async {
        await perform {
            _ = try await auth.deleteAnonymousUser()
            statusMessage = "Anonymous user deleted"
        }
    }

    // MARK: - Delete User

    public func deleteUser(_ payload: DeleteUserRequest = .init()) async {
        await perform {
            _ = try await auth.deleteUser(payload)
            statusMessage = "Account deleted"
        }
    }

    // MARK: - Anonymous Upgrade

    @discardableResult
    public func upgradeAnonymousWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await performThrowing {
            let result = try await auth.upgradeAnonymousWithEmail(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    public func upgradeAnonymousWithApple(_ payload: AppleNativeSignInPayload) async {
        await perform {
            _ = try await auth.upgradeAnonymousWithApple(payload)
            statusMessage = "Account upgraded with Apple"
        }
    }

    @discardableResult
    public func upgradeAnonymousWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        try await performThrowing {
            let result = try await auth.upgradeAnonymousWithSocial(payload)
            statusMessage = "Account upgraded"
            return result
        }
    }

    // MARK: - Re-authentication

    @discardableResult
    public func reauthenticate(password: String) async throws -> Bool {
        try await performThrowing {
            let result = try await auth.reauthenticate(password: password)
            statusMessage = "Re-authenticated"
            return result
        }
    }

    // MARK: - Magic Link

    public func requestMagicLink(_ payload: MagicLinkRequest) async {
        await perform {
            _ = try await auth.requestMagicLink(payload)
            statusMessage = "Magic link sent"
        }
    }

    public func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async {
        await perform {
            let result = try await auth.verifyMagicLink(payload)
            if case let .signedIn(session) = result {
                applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                     session: session,
                                                     transition: .init(phase: .authenticated)))
            }
            statusMessage = "Magic link verified"
        }
    }

    // MARK: - Email OTP

    public func requestEmailOTP(_ payload: EmailOTPRequest) async {
        await perform {
            _ = try await auth.requestEmailOTP(payload)
            statusMessage = "Email OTP sent"
        }
    }

    public func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async {
        await perform {
            _ = try await auth.signInWithEmailOTP(payload)
            statusMessage = "Signed in with email OTP"
        }
    }

    public func verifyEmailOTP(_ payload: EmailOTPVerifyRequest) async {
        await perform {
            let result = try await auth.verifyEmailOTP(payload)
            if case let .signedIn(session) = result {
                applyAuthStateChange(AuthStateChange(event: .signedIn,
                                                     session: session,
                                                     transition: .init(phase: .authenticated)))
            }
            statusMessage = "Email OTP verified"
        }
    }

    // MARK: - Phone OTP

    public func requestPhoneOTP(_ payload: PhoneOTPRequest) async {
        await perform {
            _ = try await auth.requestPhoneOTP(payload)
            statusMessage = "Phone OTP sent"
        }
    }

    public func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest) async {
        await perform {
            _ = try await auth.verifyPhoneNumber(payload)
            statusMessage = "Phone number verified"
        }
    }

    public func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async {
        await perform {
            _ = try await auth.signInWithPhoneOTP(payload)
            statusMessage = "Signed in with phone OTP"
        }
    }

    // MARK: - Two Factor

    @discardableResult
    public func enableTwoFactor(_ payload: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await performThrowing {
            let response = try await auth.enableTwoFactor(payload)
            statusMessage = "Two-factor enabled"
            return response
        }
    }

    public func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async {
        await perform {
            _ = try await auth.sendTwoFactorOTP(payload)
            statusMessage = "Two-factor OTP sent"
        }
    }

    public func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorTOTP(payload)
            statusMessage = "Two-factor TOTP verified"
        }
    }

    public func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorOTP(payload)
            statusMessage = "Two-factor OTP verified"
        }
    }

    public func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async {
        await perform {
            _ = try await auth.verifyTwoFactorRecoveryCode(payload)
            statusMessage = "Recovery code accepted"
        }
    }

    public func disableTwoFactor(_ payload: TwoFactorDisableRequest) async {
        await perform {
            _ = try await auth.disableTwoFactor(payload)
            statusMessage = "Two-factor disabled"
        }
    }

    @discardableResult
    public func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await performThrowing {
            let codes = try await auth.generateTwoFactorRecoveryCodes(password: password)
            statusMessage = "Backup codes generated"
            return codes
        }
    }

    // MARK: - Passkey

    @discardableResult
    public func passkeyRegistrationOptions(_ payload: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await performThrowing {
            let options = try await auth.passkeyRegistrationOptions(payload)
            statusMessage = "Passkey registration options fetched"
            return options
        }
    }

    @discardableResult
    public func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await performThrowing {
            let options = try await auth.passkeyAuthenticateOptions()
            statusMessage = "Passkey authentication options fetched"
            return options
        }
    }

    public func registerPasskey(_ payload: PasskeyRegistrationRequest) async {
        await perform {
            _ = try await auth.registerPasskey(payload)
            statusMessage = "Passkey registered"
        }
    }

    public func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async {
        await perform {
            _ = try await auth.authenticateWithPasskey(payload)
            statusMessage = "Signed in with passkey"
        }
    }

    @discardableResult
    public func listPasskeys() async throws -> [Passkey] {
        try await performThrowing {
            let passkeys = try await auth.listPasskeys()
            statusMessage = "Passkeys loaded"
            return passkeys
        }
    }

    public func updatePasskey(_ payload: UpdatePasskeyRequest) async {
        await perform {
            _ = try await auth.updatePasskey(payload)
            statusMessage = "Passkey updated"
        }
    }

    public func deletePasskey(_ payload: DeletePasskeyRequest) async {
        await perform {
            _ = try await auth.deletePasskey(payload)
            statusMessage = "Passkey deleted"
        }
    }

    // MARK: - Email Verification

    public func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async {
        await perform {
            _ = try await auth.sendVerificationEmail(payload)
            statusMessage = "Verification email sent"
        }
    }

    public func verifyEmail(_ payload: VerifyEmailRequest) async {
        await perform {
            _ = try await auth.verifyEmail(payload)
            statusMessage = "Email verified"
        }
    }

    public func changeEmail(_ payload: ChangeEmailRequest) async {
        await perform {
            _ = try await auth.changeEmail(payload)
            statusMessage = "Change email requested"
        }
    }

    // MARK: - Account Management

    public func updateUser(_ payload: UpdateUserRequest) async {
        await perform {
            _ = try await auth.updateUser(payload)
            statusMessage = "Profile updated"
        }
    }

    // MARK: - Linked Accounts

    @discardableResult
    public func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await performThrowing {
            let accounts = try await auth.listLinkedAccounts()
            statusMessage = "Linked accounts loaded"
            return accounts
        }
    }

    @discardableResult
    public func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await performThrowing {
            let response = try await auth.linkSocialAccount(payload)
            statusMessage = "Social account linked"
            return response
        }
    }

    // MARK: - Sessions

    @discardableResult
    public func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await performThrowing {
            let sessions = try await auth.listSessions()
            statusMessage = "Sessions loaded"
            return sessions
        }
    }

    @discardableResult
    public func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await performThrowing {
            let sessions = try await auth.listDeviceSessions()
            statusMessage = "Device sessions loaded"
            return sessions
        }
    }

    public func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async {
        await perform {
            _ = try await auth.setActiveDeviceSession(payload)
            statusMessage = "Active session switched"
        }
    }

    public func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async {
        await perform {
            _ = try await auth.revokeDeviceSession(payload)
            statusMessage = "Device session revoked"
        }
    }

    public func revokeSession(token: String) async {
        await perform {
            _ = try await auth.revokeSession(token: token)
            statusMessage = "Session revoked"
        }
    }

    public func revokeSessions() async {
        await perform {
            _ = try await auth.revokeSessions()
            statusMessage = "All sessions revoked"
        }
    }

    public func revokeOtherSessions() async {
        await perform {
            _ = try await auth.revokeOtherSessions()
            statusMessage = "Other sessions revoked"
        }
    }

    // MARK: - JWT

    @discardableResult
    public func getSessionJWT() async throws -> BetterAuthJWT {
        try await performThrowing {
            let jwt = try await auth.getSessionJWT()
            statusMessage = "JWT fetched"
            return jwt
        }
    }

    @discardableResult
    public func getJWKS() async throws -> BetterAuthJWKS {
        try await performThrowing {
            let jwks = try await auth.getJWKS()
            statusMessage = "JWKS fetched"
            return jwks
        }
    }

    // MARK: - Helpers

    private func startAuthStateObservation() {
        authStateTask?.cancel()
        let auth = auth
        authStateTask = Task { [weak self, auth] in
            for await change in auth.authStateChanges {
                guard !Task.isCancelled else { return }
                guard let self else { return }
                self.applyAuthStateChange(change)
            }
        }
    }

    private func stopAuthStateObservation() {
        authStateTask?.cancel()
        authStateTask = nil
    }

    private func applyRestoreResult(_ result: BetterAuthRestoreResult) {
        switch result {
        case .noStoredSession:
            session = nil
            launchState = .unauthenticated
            statusMessage = "No stored session"

        case let .restored(restoredSession, _, refresh):
            session = restoredSession
            switch refresh {
            case .notNeeded:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored"

            case .refreshed:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored and refreshed"

            case .deferred:
                launchState = .recoverableFailure(restoredSession)
                statusMessage = "Session restored; refresh deferred"

            @unknown default:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored"
            }

        case .cleared:
            session = nil
            launchState = .unauthenticated
            statusMessage = "Stored session cleared"

        @unknown default:
            session = nil
            launchState = .unauthenticated
            statusMessage = "Session state updated"
        }
    }

    private func applyAuthStateChange(_ change: AuthStateChange) {
        session = change.session
        switch change.transition?.phase {
        case .authenticated:
            if let session = change.session {
                launchState = .authenticated(session)
            }

        case .unauthenticated:
            launchState = .unauthenticated

        case .refreshing:
            if let session = change.session {
                launchState = .authenticated(session)
            }

        case .restoring:
            launchState = .restoring

        case .failed:
            launchState = .failed

        case .idle, nil:
            if let session = change.session {
                launchState = .authenticated(session)
            } else if change.event == .signedOut || change.event == .sessionExpired {
                launchState = .unauthenticated
            }

        @unknown default:
            if let session = change.session {
                launchState = .authenticated(session)
            } else if change.event == .signedOut || change.event == .sessionExpired {
                launchState = .unauthenticated
            }
        }
    }

    private func perform(_ operation: () async throws -> Void) async {
        isLoading = true
        defer { isLoading = false }
        do {
            try Task.checkCancellation()
            try await operation()
            lastError = nil
        } catch {
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
        }
    }

    private func performThrowing<T>(_ operation: () async throws -> T) async throws -> T {
        isLoading = true
        defer { isLoading = false }
        do {
            try Task.checkCancellation()
            let result = try await operation()
            lastError = nil
            return result
        } catch {
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
            throw error
        }
    }

    private func normalizeError(_ error: Error) -> BetterAuthError? {
        if let betterAuthError = error as? BetterAuthError {
            return betterAuthError
        }
        return nil
    }

    public func shutdown() {
        stopAuthStateObservation()
    }
}
