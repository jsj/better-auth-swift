import AuthenticationServices
import BetterAuth
import Foundation
import Observation

@Observable
@MainActor
final class AuthViewModel {
    enum WorkerReachability {
        case checking
        case reachable
        case unreachable

        var statusText: String {
            switch self {
            case .checking:
                "Checking worker"
            case .reachable:
                "Worker reachable"
            case .unreachable:
                "Worker unreachable"
            }
        }
    }

    let configuration: AuthConfiguration
    var session: BetterAuthSession?
    var statusMessage: String?
    var isReady = false
    var isPerformingAuthAction = false
    var lastPayload: AppleNativeSignInPayload?
    var workerReachability: WorkerReachability = .checking

    // Email / Password
    var emailInput = ""
    var passwordInput = ""
    var nameInput = ""
    var usernameInput = ""
    var newPasswordInput = ""

    // OTP / Token
    var otpInput = ""
    var tokenInput = ""

    // Two-factor
    var twoFactorTOTPInput = ""
    var twoFactorOTPInput = ""
    var twoFactorRecoveryInput = ""
    var twoFactorPassword = ""

    // Change / reset
    var newEmailInput = ""
    var resetTokenInput = ""

    // Results
    var sessionList: [BetterAuthSessionListEntry] = []
    var deviceSessions: [BetterAuthDeviceSession] = []
    var linkedAccounts: [LinkedAccount] = []
    var passkeys: [Passkey] = []
    var backupCodes: [String] = []
    var twoFactorSecret: String?
    var jwtToken: String?

    private let client: BetterAuthClient
    private let service: AuthService
    private var currentAppleContext: AppleSignInSupport.Context?

    init(configuration: AuthConfiguration, client: BetterAuthClient? = nil) {
        self.configuration = configuration
        let resolvedClient = client ?? BetterAuthClient(
            baseURL: configuration.apiBaseURL,
            storage: .init(
                key: "better-auth.example.session",
                service: "BetterAuthUIKitExample"
            )
        )
        self.client = resolvedClient
        service = AuthService(client: resolvedClient)
        statusMessage = configuration.statusMessage
    }

    #if DEBUG
    var debugClient: BetterAuthClient { client }
    #endif

    // MARK: - Session Lifecycle

    func restore() async {
        await refreshWorkerReachability()
        await perform {
            session = try await service.restoreSession()
            statusMessage = session == nil ? "No stored session" : "Session restored"
        }
        isReady = true
    }

    func refresh() async {
        await perform {
            session = try await service.refreshSession()
            statusMessage = "Session refreshed"
        }
    }

    func refreshWorkerReachability() async {
        workerReachability = .checking
        workerReachability = await service.isWorkerReachable() ? .reachable : .unreachable
    }

    func signOut() async {
        await perform {
            do {
                try await service.signOut(remotely: true)
            } catch {
                try await service.signOut(remotely: false)
            }
            session = nil
            statusMessage = "Signed out"
        }
    }

    // MARK: - Apple

    func prepareAppleRequest(_ request: ASAuthorizationAppleIDRequest) {
        let context = AppleSignInSupport.makeContext()
        currentAppleContext = context
        AppleSignInBridge.configure(request, context: context)
    }

    func handleAppleResult(_ result: Result<ASAuthorization, Error>) async {
        await perform {
            switch result {
            case let .success(authorization):
                let payload = try AppleSignInBridge.payload(from: authorization, context: currentAppleContext)
                lastPayload = payload
                session = try await service.signInWithApple(payload)
                statusMessage = "Signed in with Apple"
            case let .failure(error):
                throw error
            }
        }
    }

    // MARK: - Email + Password

    func signUpWithEmail() async {
        await perform {
            let result = try await service.signUpWithEmail(.init(
                email: emailInput,
                password: passwordInput,
                name: nameInput.isEmpty ? emailInput : nameInput
            ))
            switch result {
            case let .signedIn(s):
                session = s
                statusMessage = "Signed up and signed in"
            case .signedUp:
                statusMessage = "Signed up — check your inbox to verify"
            case .verificationHeld:
                statusMessage = "Sign-up held for verification"
            }
        }
    }

    func signInWithEmail() async {
        await perform {
            session = try await service.signInWithEmail(.init(
                email: emailInput,
                password: passwordInput
            ))
            statusMessage = "Signed in"
        }
    }

    func requestPasswordReset() async {
        await perform {
            try await service.requestPasswordReset(.init(email: emailInput))
            statusMessage = "Password reset email sent"
        }
    }

    func resetPassword() async {
        await perform {
            try await service.resetPassword(.init(
                token: resetTokenInput,
                newPassword: newPasswordInput
            ))
            statusMessage = "Password reset"
        }
    }

    func changePassword() async {
        await perform {
            try await service.changePassword(.init(
                currentPassword: passwordInput,
                newPassword: newPasswordInput
            ))
            statusMessage = "Password changed"
        }
    }

    // MARK: - Username

    func checkUsernameAvailability() async {
        await perform {
            let available = try await service.isUsernameAvailable(.init(username: usernameInput))
            statusMessage = available ? "'\(usernameInput)' is available" : "'\(usernameInput)' is taken"
        }
    }

    func signInWithUsername() async {
        await perform {
            session = try await service.signInWithUsername(.init(
                username: usernameInput,
                password: passwordInput
            ))
            statusMessage = "Signed in with username"
        }
    }

    // MARK: - Magic Link

    func requestMagicLink() async {
        await perform {
            try await service.requestMagicLink(.init(email: emailInput))
            statusMessage = "Magic link sent to \(emailInput)"
        }
    }

    func verifyMagicLink() async {
        await perform {
            let result = try await service.verifyMagicLink(.init(token: tokenInput))
            if case let .signedIn(s) = result { session = s }
            statusMessage = "Magic link verified"
        }
    }

    // MARK: - Email OTP

    func requestEmailOTP() async {
        await perform {
            try await service.requestEmailOTP(.init(email: emailInput, type: .signIn))
            statusMessage = "Email OTP sent to \(emailInput)"
        }
    }

    func signInWithEmailOTP() async {
        await perform {
            session = try await service.signInWithEmailOTP(.init(
                email: emailInput,
                otp: otpInput
            ))
            statusMessage = "Signed in with email OTP"
        }
    }

    func verifyEmailOTP() async {
        await perform {
            let result = try await service.verifyEmailOTP(.init(
                email: emailInput,
                otp: otpInput
            ))
            if case let .signedIn(s) = result { session = s }
            statusMessage = "Email OTP verified"
        }
    }

    // MARK: - Phone OTP

    func requestPhoneOTP() async {
        await perform {
            try await service.requestPhoneOTP(.init(phoneNumber: otpInput))
            statusMessage = "Phone OTP sent"
        }
    }

    func verifyPhoneOTP() async {
        await perform {
            try await service.verifyPhoneNumber(.init(
                phoneNumber: otpInput,
                code: tokenInput
            ))
            statusMessage = "Phone number verified"
        }
    }

    func signInWithPhoneOTP() async {
        await perform {
            session = try await service.signInWithPhoneOTP(.init(
                phoneNumber: otpInput,
                password: tokenInput
            ))
            statusMessage = "Signed in with phone OTP"
        }
    }

    // MARK: - Two Factor

    func enableTwoFactor() async {
        await perform {
            let response = try await service.enableTwoFactor(.init(password: passwordInput))
            twoFactorSecret = response.totpURI
            statusMessage = "Two-factor enabled"
        }
    }

    func sendTwoFactorOTP() async {
        await perform {
            try await service.sendTwoFactorOTP()
            statusMessage = "Two-factor OTP sent"
        }
    }

    func verifyTwoFactorTOTP() async {
        await perform {
            session = try await service.verifyTwoFactorTOTP(.init(code: twoFactorTOTPInput))
            statusMessage = "Two-factor TOTP verified"
        }
    }

    func verifyTwoFactorOTP() async {
        await perform {
            session = try await service.verifyTwoFactorOTP(.init(code: twoFactorOTPInput))
            statusMessage = "Two-factor OTP verified"
        }
    }

    func verifyTwoFactorRecovery() async {
        await perform {
            session = try await service.verifyTwoFactorRecoveryCode(.init(code: twoFactorRecoveryInput))
            statusMessage = "Recovery code accepted"
        }
    }

    func generateBackupCodes() async {
        await perform {
            backupCodes = try await service.generateTwoFactorRecoveryCodes(password: twoFactorPassword)
            statusMessage = "\(backupCodes.count) backup codes generated"
        }
    }

    // MARK: - Email Verification

    func sendVerificationEmail() async {
        await perform {
            try await service.sendVerificationEmail()
            statusMessage = "Verification email sent"
        }
    }

    func verifyEmail() async {
        await perform {
            let result = try await service.verifyEmail(.init(token: tokenInput))
            if case let .signedIn(s) = result { session = s }
            statusMessage = "Email verified"
        }
    }

    func changeEmail() async {
        await perform {
            try await service.changeEmail(.init(newEmail: newEmailInput))
            statusMessage = "Change email requested — check both inboxes"
        }
    }

    // MARK: - Profile

    func updateDisplayName() async {
        await perform {
            let response = try await service.updateUser(.init(name: nameInput.isEmpty ? nil : nameInput))
            if let current = session, let updatedUser = response.user {
                session = BetterAuthSession(session: current.session, user: updatedUser)
            }
            statusMessage = "Name updated"
        }
    }

    // MARK: - Sessions

    func loadSessions() async {
        await perform {
            sessionList = try await service.listSessions()
            statusMessage = "\(sessionList.count) session(s) loaded"
        }
    }

    func loadDeviceSessions() async {
        await perform {
            deviceSessions = try await service.listDeviceSessions()
            statusMessage = "\(deviceSessions.count) device session(s) loaded"
        }
    }

    func revokeOtherSessions() async {
        await perform {
            try await service.revokeOtherSessions()
            statusMessage = "Other sessions revoked"
        }
    }

    func revokeSessions() async {
        await perform {
            try await service.revokeSessions()
            session = nil
            statusMessage = "All sessions revoked"
        }
    }

    // MARK: - Linked Accounts

    func loadLinkedAccounts() async {
        await perform {
            linkedAccounts = try await service.listLinkedAccounts()
            statusMessage = "\(linkedAccounts.count) linked account(s)"
        }
    }

    // MARK: - Passkeys

    func loadPasskeys() async {
        await perform {
            passkeys = try await service.listPasskeys()
            statusMessage = "\(passkeys.count) passkey(s) loaded"
        }
    }

    // MARK: - JWT

    func loadJWT() async {
        await perform {
            let jwt = try await service.getSessionJWT()
            jwtToken = jwt.token
            statusMessage = "JWT loaded"
        }
    }

    // MARK: - Anonymous

    func signInAnonymously() async {
        await perform {
            session = try await service.signInAnonymously()
            statusMessage = "Signed in anonymously"
        }
    }

    func deleteAnonymousUser() async {
        await perform {
            try await service.deleteAnonymousUser()
            session = nil
            statusMessage = "Anonymous user deleted"
        }
    }

    // MARK: - Private

    private func perform(_ operation: () async throws -> Void) async {
        isPerformingAuthAction = true
        defer { isPerformingAuthAction = false }
        do {
            try await operation()
        } catch {
            statusMessage = error.localizedDescription
        }
    }
}
