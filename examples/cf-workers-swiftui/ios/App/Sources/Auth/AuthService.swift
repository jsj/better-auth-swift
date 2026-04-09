import BetterAuth
import Foundation

struct AuthService {
    private let client: BetterAuthClient
    private let session: URLSession

    init(client: BetterAuthClient, session: URLSession = .shared) {
        self.client = client
        self.session = session
    }

    func restoreSession() async throws -> BetterAuthSession? {
        try await client.auth.restoreOrRefreshSession()
    }

    func restoreSessionOnLaunch() async throws -> BetterAuthRestoreResult {
        try await client.auth.restoreSessionOnLaunch()
    }

    func refreshSession() async throws -> BetterAuthSession? {
        try await client.auth.refreshSession()
    }

    func isSupportedIncomingURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            return false
        }

        let path = components.path
        let queryItems = components.queryItems ?? []

        if queryItems.first(where: { $0.name == "code" })?.value != nil,
           queryItems.first(where: { $0.name == "state" })?.value != nil
        {
            let pathComponents = path.split(separator: "/")
            if let callbackIndex = pathComponents.firstIndex(of: "callback"), callbackIndex + 1 < pathComponents.count {
                return true
            }
        }

        if path.hasSuffix(client.configuration.endpoints.magicLinkVerifyPath),
           queryItems.first(where: { $0.name == "token" })?.value != nil
        {
            return true
        }

        if path.hasSuffix(client.configuration.endpoints.verifyEmailPath),
           queryItems.first(where: { $0.name == "token" })?.value != nil
        {
            return true
        }

        return false
    }

    func handleIncomingURL(_ url: URL) async throws -> BetterAuthHandledURLResult {
        try await client.auth.handleIncomingURL(url)
    }

    func signOut(remotely: Bool) async throws {
        try await client.auth.signOut(remotely: remotely)
    }

    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await client.auth.signInWithApple(payload)
    }

    func signUpWithEmail(_ request: EmailSignUpRequest) async throws -> EmailSignUpResult {
        try await client.auth.signUpWithEmail(request)
    }

    func signInWithEmail(_ request: EmailSignInRequest) async throws -> BetterAuthSession {
        try await client.auth.signInWithEmail(request)
    }

    func requestPasswordReset(_ request: ForgotPasswordRequest) async throws {
        _ = try await client.auth.requestPasswordReset(request)
    }

    func resetPassword(_ request: ResetPasswordRequest) async throws {
        _ = try await client.auth.resetPassword(request)
    }

    func changePassword(_ request: ChangePasswordRequest) async throws {
        _ = try await client.auth.changePassword(request)
    }

    func isUsernameAvailable(_ request: UsernameAvailabilityRequest) async throws -> Bool {
        try await client.auth.isUsernameAvailable(request)
    }

    func signInWithUsername(_ request: UsernameSignInRequest) async throws -> BetterAuthSession {
        try await client.auth.signInWithUsername(request)
    }

    func requestMagicLink(_ request: MagicLinkRequest) async throws {
        _ = try await client.auth.requestMagicLink(request)
    }

    func verifyMagicLink(_ request: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        try await client.auth.verifyMagicLink(request)
    }

    func requestEmailOTP(_ request: EmailOTPRequest) async throws {
        _ = try await client.auth.requestEmailOTP(request)
    }

    func signInWithEmailOTP(_ request: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        try await client.auth.signInWithEmailOTP(request)
    }

    func verifyEmailOTP(_ request: EmailOTPVerifyRequest) async throws -> EmailOTPVerifyResult {
        try await client.auth.verifyEmailOTP(request)
    }

    func requestPhoneOTP(_ request: PhoneOTPRequest) async throws {
        _ = try await client.auth.requestPhoneOTP(request)
    }

    func verifyPhoneNumber(_ request: PhoneOTPVerifyRequest) async throws {
        _ = try await client.auth.verifyPhoneNumber(request)
    }

    func signInWithPhoneOTP(_ request: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        try await client.auth.signInWithPhoneOTP(request)
    }

    func enableTwoFactor(_ request: TwoFactorEnableRequest) async throws -> TwoFactorEnableResponse {
        try await client.auth.enableTwoFactor(request)
    }

    func sendTwoFactorOTP() async throws {
        _ = try await client.auth.sendTwoFactorOTP()
    }

    func verifyTwoFactorTOTP(_ request: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        try await client.auth.verifyTwoFactorTOTP(request)
    }

    func verifyTwoFactorOTP(_ request: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        try await client.auth.verifyTwoFactorOTP(request)
    }

    func verifyTwoFactorRecoveryCode(_ request: TwoFactorVerifyBackupCodeRequest) async throws -> BetterAuthSession {
        try await client.auth.verifyTwoFactorRecoveryCode(request)
    }

    func generateTwoFactorRecoveryCodes(password: String) async throws -> [String] {
        try await client.auth.generateTwoFactorRecoveryCodes(password: password)
    }

    func sendVerificationEmail() async throws {
        _ = try await client.auth.sendVerificationEmail()
    }

    func verifyEmail(_ request: VerifyEmailRequest) async throws -> VerifyEmailResult {
        try await client.auth.verifyEmail(request)
    }

    func changeEmail(_ request: ChangeEmailRequest) async throws {
        _ = try await client.auth.changeEmail(request)
    }

    func updateUser(_ request: UpdateUserRequest) async throws -> UpdateUserResponse {
        try await client.auth.updateUser(request)
    }

    func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await client.auth.listSessions()
    }

    func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await client.auth.listDeviceSessions()
    }

    func revokeOtherSessions() async throws {
        _ = try await client.auth.revokeOtherSessions()
    }

    func revokeSessions() async throws {
        _ = try await client.auth.revokeSessions()
    }

    func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await client.auth.listLinkedAccounts()
    }

    func listPasskeys() async throws -> [Passkey] {
        try await client.auth.listPasskeys()
    }

    func getSessionJWT() async throws -> BetterAuthJWT {
        try await client.auth.getSessionJWT()
    }

    func signInAnonymously() async throws -> BetterAuthSession {
        try await client.auth.signInAnonymously()
    }

    func deleteAnonymousUser() async throws {
        _ = try await client.auth.deleteAnonymousUser()
    }

    func deleteUser() async throws {
        _ = try await client.auth.deleteUser()
    }

    func isWorkerReachable() async -> Bool {
        var request = URLRequest(url: client.configuration.baseURL)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 3

        do {
            let (_, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                return false
            }
            return (200 ..< 500).contains(httpResponse.statusCode)
        } catch {
            return false
        }
    }
}
