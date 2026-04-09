import AuthenticationServices
import UIKit

@MainActor
final class AuthOptionController {
    let viewModel: AuthViewModel

    init(viewModel: AuthViewModel) {
        self.viewModel = viewModel
    }

    func currentStatusText() -> String {
        viewModel.statusMessage ?? "No status yet"
    }

    func sections(for option: AuthOption) -> [AuthOptionSectionModel] {
        switch option {
        case .authMethod(.apple):
            [.init(title: "Actions",
                   rows: [.action(model: .init(title: "Sign in with Apple",
                                               detail: "Launch the native Apple sign-in sheet.",
                                               symbolName: "apple.logo",
                                               action: .appleSignIn)),
                          .info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor())]),
             .init(title: "Expected Inputs",
                   rows: [.info(title: "Authorization Token", detail: "Returned by Apple after successful native auth.",
                                symbolName: "key.fill"),
                          .info(title: "Nonce", detail: "Generated per request and validated on callback.",
                                symbolName: "number"),
                          .info(title: "Profile Hints",
                                detail: "Email and names may only be present on first authorization.",
                                symbolName: "person.text.rectangle")])]

        case .authMethod(.emailPassword):
            formSections(summary: "Create accounts, sign in, request resets, and change passwords.",
                         fields: [.text(label: "Email", keyPath: \.emailInput, keyboard: .emailAddress, secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Password", keyPath: \.passwordInput, keyboard: .default, secure: true,
                                        autocapitalization: .none),
                                  .text(label: "Name", keyPath: \.nameInput, keyboard: .default, secure: false,
                                        autocapitalization: .words),
                                  .text(label: "Reset Token", keyPath: \.resetTokenInput, keyboard: .default,
                                        secure: false,
                                        autocapitalization: .none),
                                  .text(label: "New Password", keyPath: \.newPasswordInput, keyboard: .default,
                                        secure: true,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Sign Up", detail: "Create a new account.",
                                         symbolName: "person.badge.plus",
                                         action: .signUpWithEmail),
                                   .init(title: "Sign In", detail: "Authenticate with email and password.",
                                         symbolName: "arrow.right.circle", action: .signInWithEmail),
                                   .init(title: "Request Password Reset", detail: "Send a reset email.",
                                         symbolName: "envelope.badge",
                                         action: .requestPasswordReset),
                                   .init(title: "Reset Password", detail: "Submit token and new password.",
                                         symbolName: "key.horizontal", action: .resetPassword),
                                   .init(title: "Change Password", detail: "Change password for the current session.",
                                         symbolName: "lock.rotation", action: .changePassword)])

        case .authMethod(.usernamePassword):
            formSections(summary: "Check username availability and sign in with username/password.",
                         fields: [.text(label: "Username", keyPath: \.usernameInput, keyboard: .default, secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Password", keyPath: \.passwordInput, keyboard: .default, secure: true,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Check Availability", detail: "Validate username availability.",
                                         symbolName: "checkmark.seal", action: .checkUsernameAvailability),
                                   .init(title: "Sign In with Username",
                                         detail: "Authenticate with username and password.",
                                         symbolName: "person.crop.circle.badge.checkmark",
                                         action: .signInWithUsername)])

        case .authMethod(.magicLink):
            formSections(summary: "Request sign-in links and verify returned link tokens.",
                         fields: [.text(label: "Email", keyPath: \.emailInput, keyboard: .emailAddress, secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Token", keyPath: \.tokenInput, keyboard: .default, secure: false,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Send Magic Link", detail: "Send an email sign-in link.",
                                         symbolName: "link.badge.plus", action: .requestMagicLink),
                                   .init(title: "Verify Magic Link", detail: "Submit the returned link token.",
                                         symbolName: "checkmark.circle", action: .verifyMagicLink)])

        case .authMethod(.emailOTP):
            formSections(summary: "Request and verify one-time email codes for auth flows.",
                         fields: [.text(label: "Email", keyPath: \.emailInput, keyboard: .emailAddress, secure: false,
                                        autocapitalization: .none),
                                  .text(label: "OTP Code", keyPath: \.otpInput, keyboard: .numberPad, secure: false,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Request OTP", detail: "Send an email OTP.",
                                         symbolName: "envelope.badge.shield.half.filled", action: .requestEmailOTP),
                                   .init(title: "Sign In with OTP", detail: "Authenticate with email OTP.",
                                         symbolName: "person.badge.key", action: .signInWithEmailOTP),
                                   .init(title: "Verify OTP", detail: "Verify email using OTP.",
                                         symbolName: "checkmark.shield",
                                         action: .verifyEmailOTP)])

        case .authMethod(.phoneOTP):
            formSections(summary: "Request phone codes, verify numbers, and sign in with OTP.",
                         fields: [.text(label: "Phone Number", keyPath: \.otpInput, keyboard: .phonePad, secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Code / Password", keyPath: \.tokenInput, keyboard: .default,
                                        secure: false,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Request Phone OTP", detail: "Send a verification code by phone.",
                                         symbolName: "message.badge", action: .requestPhoneOTP),
                                   .init(title: "Verify Phone Number", detail: "Verify a phone number with the code.",
                                         symbolName: "phone.badge.checkmark", action: .verifyPhoneOTP),
                                   .init(title: "Sign In with Phone OTP", detail: "Authenticate with phone OTP.",
                                         symbolName: "phone.connection", action: .signInWithPhoneOTP)])

        case .authMethod(.twoFactor):
            formSections(summary: "Enable 2FA, verify TOTP/OTP challenges, and manage recovery codes.",
                         fields: [.text(label: "Current Password", keyPath: \.passwordInput, keyboard: .default,
                                        secure: true,
                                        autocapitalization: .none),
                                  .text(label: "TOTP Code", keyPath: \.twoFactorTOTPInput, keyboard: .numberPad,
                                        secure: false,
                                        autocapitalization: .none),
                                  .text(label: "OTP Code", keyPath: \.twoFactorOTPInput, keyboard: .numberPad,
                                        secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Recovery Code", keyPath: \.twoFactorRecoveryInput, keyboard: .default,
                                        secure: false,
                                        autocapitalization: .none),
                                  .text(label: "Password for Backup Codes", keyPath: \.twoFactorPassword,
                                        keyboard: .default,
                                        secure: true, autocapitalization: .none)],
                         actions: [.init(title: "Enable 2FA", detail: "Enable two-factor protection.",
                                         symbolName: "lock.shield",
                                         action: .enableTwoFactor),
                                   .init(title: "Send 2FA OTP", detail: "Send a one-time code.",
                                         symbolName: "paperplane",
                                         action: .sendTwoFactorOTP),
                                   .init(title: "Verify TOTP", detail: "Verify authenticator app code.",
                                         symbolName: "checkmark.circle", action: .verifyTwoFactorTOTP),
                                   .init(title: "Verify 2FA OTP", detail: "Verify sent OTP code.",
                                         symbolName: "checkmark.circle",
                                         action: .verifyTwoFactorOTP),
                                   .init(title: "Use Recovery Code", detail: "Recover with a backup code.",
                                         symbolName: "lifepreserver", action: .verifyTwoFactorRecovery),
                                   .init(title: "Generate Backup Codes", detail: "Create recovery codes.",
                                         symbolName: "doc.on.doc",
                                         action: .generateBackupCodes)])

        case .emailVerification:
            formSections(summary: "Trigger verification email sends and complete email verification / change requests.",
                         fields: [.text(label: "Verification Token", keyPath: \.tokenInput, keyboard: .default,
                                        secure: false,
                                        autocapitalization: .none),
                                  .text(label: "New Email Address", keyPath: \.newEmailInput, keyboard: .emailAddress,
                                        secure: false,
                                        autocapitalization: .none)],
                         actions: [.init(title: "Send Verification Email", detail: "Send a verification message.",
                                         symbolName: "envelope.open", action: .sendVerificationEmail),
                                   .init(title: "Verify Email", detail: "Complete email verification.",
                                         symbolName: "checkmark.seal",
                                         action: .verifyEmail),
                                   .init(title: "Request Email Change", detail: "Start an email change flow.",
                                         symbolName: "arrow.triangle.2.circlepath", action: .changeEmail)])

        case .profile:
            formSections(summary: "Update the authenticated user's visible profile fields.",
                         fields: [.text(label: "Display Name", keyPath: \.nameInput, keyboard: .default, secure: false,
                                        autocapitalization: .words)],
                         actions: [.init(title: "Update Name", detail: "Save the display name to the current user.",
                                         symbolName: "person.crop.circle.badge.checkmark", action: .updateDisplayName)])

        case .sessionManagement:
            [.init(title: "Summary",
                   rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor()),
                          .info(title: "Supports",
                                detail: "List sessions, inspect device sessions, revoke other sessions, and revoke all sessions.",
                                symbolName: "rectangle.stack.badge.person.crop")]),
             .init(title: "Actions",
                   rows: [.action(model: .init(title: "Load Sessions", detail: "Fetch all sessions.",
                                               symbolName: "list.bullet.rectangle", action: .loadSessions)),
                          .action(model: .init(title: "Load Device Sessions", detail: "Fetch device-scoped sessions.",
                                               symbolName: "iphone.gen3", action: .loadDeviceSessions)),
                          .action(model: .init(title: "Revoke Other Sessions", detail: "Sign out other devices.",
                                               symbolName: "person.crop.circle.badge.minus",
                                               action: .revokeOtherSessions)),
                          .action(model: .init(title: "Revoke All Sessions", detail: "Revoke all sessions.",
                                               symbolName: "trash", action: .revokeSessions))])]

        case .linkedAccounts:
            [.init(title: "Summary",
                   rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor()),
                          .info(title: "Supports", detail: "Load linked provider accounts from the shared auth client.",
                                symbolName: "person.2.badge.key")]),
             .init(title: "Actions",
                   rows: [.action(model: .init(title: "Load Linked Accounts", detail: "Fetch linked provider accounts.",
                                               symbolName: "person.2.badge.key", action: .loadLinkedAccounts))])]

        case .authMethod(.passkey):
            [.init(title: "Summary",
                   rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor()),
                          .info(title: "Supports",
                                detail: "Inspect passkeys already registered for the signed-in user.",
                                symbolName: "key.viewfinder")]),
             .init(title: "Actions",
                   rows: [.action(model: .init(title: "Load Passkeys", detail: "Fetch passkeys for the current user.",
                                               symbolName: "key.viewfinder", action: .loadPasskeys))])]

        case .jwt:
            [.init(title: "Summary",
                   rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor()),
                          .info(title: "Supports", detail: "Fetch a JWT from the current authenticated session.",
                                symbolName: "doc.text.magnifyingglass")]),
             .init(title: "Actions",
                   rows: [.action(model: .init(title: "Get Session JWT", detail: "Fetch a JWT token.",
                                               symbolName: "doc.text.magnifyingglass", action: .loadJWT))])]

        case .authMethod(.anonymous):
            [.init(title: "Summary",
                   rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                                tintColor: statusColor()),
                          .info(title: "Supports",
                                detail: "Create an anonymous session and later delete the anonymous user.",
                                symbolName: "person.crop.circle.badge.questionmark")]),
             .init(title: "Actions",
                   rows: [.action(model: .init(title: "Sign In Anonymously", detail: "Create an anonymous session.",
                                               symbolName: "person.badge.plus", action: .signInAnonymously)),
                          .action(model: .init(title: "Delete Anonymous User", detail: "Delete the anonymous account.",
                                               symbolName: "person.badge.minus", action: .deleteAnonymousUser))])]
        }
    }

    private func formSections(summary: String,
                              fields: [AuthFieldModel],
                              actions: [AuthActionModel]) -> [AuthOptionSectionModel]
    {
        [.init(title: "Summary",
               rows: [.info(title: "Current Status", detail: currentStatusText(), symbolName: "waveform.path.ecg",
                            tintColor: statusColor()),
                      .info(title: "Supports", detail: summary, symbolName: "info.circle")]),
         .init(title: "Fields",
               rows: fields.map { .field($0) }),
         .init(title: "Actions",
               rows: actions.map { .action(model: $0) })]
    }

    func perform(_ action: AuthAction) async {
        switch action {
        case .appleSignIn:
            break

        case .signUpWithEmail:
            await viewModel.signUpWithEmail()

        case .signInWithEmail:
            await viewModel.signInWithEmail()

        case .requestPasswordReset:
            await viewModel.requestPasswordReset()

        case .resetPassword:
            await viewModel.resetPassword()

        case .changePassword:
            await viewModel.changePassword()

        case .checkUsernameAvailability:
            await viewModel.checkUsernameAvailability()

        case .signInWithUsername:
            await viewModel.signInWithUsername()

        case .requestMagicLink:
            await viewModel.requestMagicLink()

        case .verifyMagicLink:
            await viewModel.verifyMagicLink()

        case .requestEmailOTP:
            await viewModel.requestEmailOTP()

        case .signInWithEmailOTP:
            await viewModel.signInWithEmailOTP()

        case .verifyEmailOTP:
            await viewModel.verifyEmailOTP()

        case .requestPhoneOTP:
            await viewModel.requestPhoneOTP()

        case .verifyPhoneOTP:
            await viewModel.verifyPhoneOTP()

        case .signInWithPhoneOTP:
            await viewModel.signInWithPhoneOTP()

        case .enableTwoFactor:
            await viewModel.enableTwoFactor()

        case .sendTwoFactorOTP:
            await viewModel.sendTwoFactorOTP()

        case .verifyTwoFactorTOTP:
            await viewModel.verifyTwoFactorTOTP()

        case .verifyTwoFactorOTP:
            await viewModel.verifyTwoFactorOTP()

        case .verifyTwoFactorRecovery:
            await viewModel.verifyTwoFactorRecovery()

        case .generateBackupCodes:
            await viewModel.generateBackupCodes()

        case .sendVerificationEmail:
            await viewModel.sendVerificationEmail()

        case .verifyEmail:
            await viewModel.verifyEmail()

        case .changeEmail:
            await viewModel.changeEmail()

        case .updateDisplayName:
            await viewModel.updateDisplayName()

        case .loadSessions:
            await viewModel.loadSessions()

        case .loadDeviceSessions:
            await viewModel.loadDeviceSessions()

        case .revokeOtherSessions:
            await viewModel.revokeOtherSessions()

        case .revokeSessions:
            await viewModel.revokeSessions()

        case .loadLinkedAccounts:
            await viewModel.loadLinkedAccounts()

        case .loadPasskeys:
            await viewModel.loadPasskeys()

        case .loadJWT:
            await viewModel.loadJWT()

        case .signInAnonymously:
            await viewModel.signInAnonymously()

        case .deleteAnonymousUser:
            await viewModel.deleteAnonymousUser()
        }
    }

    private func statusColor() -> UIColor {
        guard let status = viewModel.statusMessage?.lowercased() else {
            return .secondaryLabel
        }

        if status.contains("signed in") || status.contains("restored") || status.contains("reachable") || status
            .contains("loaded") || status.contains("enabled") || status.contains("verified")
        {
            return .systemGreen
        }

        if status.contains("error") || status.contains("invalid") || status.contains("failed") || status
            .contains("missing") || status.contains("unreachable")
        {
            return .systemRed
        }

        return .systemOrange
    }
}

struct AuthOptionSectionModel {
    let title: String
    let rows: [AuthOptionRowModel]
}

enum AuthOptionRowModel {
    case info(title: String, detail: String, symbolName: String? = nil, tintColor: UIColor? = nil)
    case bullet(String, symbolName: String? = nil)
    case field(AuthFieldModel)
    case action(model: AuthActionModel)
}

struct AuthFieldModel {
    let label: String
    let keyPath: ReferenceWritableKeyPath<AuthViewModel, String>
    let keyboard: UIKeyboardType
    let secure: Bool
    let autocapitalization: UITextAutocapitalizationType

    static func text(label: String,
                     keyPath: ReferenceWritableKeyPath<AuthViewModel, String>,
                     keyboard: UIKeyboardType,
                     secure: Bool,
                     autocapitalization: UITextAutocapitalizationType) -> AuthFieldModel
    {
        .init(label: label,
              keyPath: keyPath,
              keyboard: keyboard,
              secure: secure,
              autocapitalization: autocapitalization)
    }
}

struct AuthActionModel {
    let title: String
    let detail: String
    let symbolName: String
    let action: AuthAction
}

enum AuthAction {
    case appleSignIn
    case signUpWithEmail
    case signInWithEmail
    case requestPasswordReset
    case resetPassword
    case changePassword
    case checkUsernameAvailability
    case signInWithUsername
    case requestMagicLink
    case verifyMagicLink
    case requestEmailOTP
    case signInWithEmailOTP
    case verifyEmailOTP
    case requestPhoneOTP
    case verifyPhoneOTP
    case signInWithPhoneOTP
    case enableTwoFactor
    case sendTwoFactorOTP
    case verifyTwoFactorTOTP
    case verifyTwoFactorOTP
    case verifyTwoFactorRecovery
    case generateBackupCodes
    case sendVerificationEmail
    case verifyEmail
    case changeEmail
    case updateDisplayName
    case loadSessions
    case loadDeviceSessions
    case revokeOtherSessions
    case revokeSessions
    case loadLinkedAccounts
    case loadPasskeys
    case loadJWT
    case signInAnonymously
    case deleteAnonymousUser
}
