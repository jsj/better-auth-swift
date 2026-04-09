import AuthenticationServices
import BetterAuth
import SwiftUI

struct AppleAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("Apple Sign In") {
            SignInWithAppleButton(.signIn) { request in
                viewModel.prepareAppleRequest(request)
            } onCompletion: { result in
                Task { await viewModel.handleAppleResult(result) }
            }
            .signInWithAppleButtonStyle(.black)
            .frame(height: 44)
            .disabled(viewModel.isPerformingAuthAction)

            if let payload = viewModel.lastPayload {
                LabeledContent("Email", value: payload.email ?? "—")
                LabeledContent("Given Name", value: payload.givenName ?? "—")
                LabeledContent("Family Name", value: payload.familyName ?? "—")
                LabeledContent("Nonce", value: payload.nonce.map { String($0.prefix(12)) + "…" } ?? "—")
            }
        }
    }
}

struct EmailPasswordAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Email + Password") {
            TextField("Email", text: $viewModel.emailInput)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            SecureField("Password", text: $viewModel.passwordInput)
            TextField("Name (sign-up)", text: $viewModel.nameInput)
                .autocapitalization(.words)
            Button("Sign Up") { Task { await viewModel.signUpWithEmail() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty || viewModel.passwordInput
                    .isEmpty)
            Button("Sign In") { Task { await viewModel.signInWithEmail() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty || viewModel.passwordInput
                    .isEmpty)
            Button("Request Password Reset") { Task { await viewModel.requestPasswordReset() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty)
        }

        Section("Reset Password") {
            TextField("Reset Token", text: $viewModel.resetTokenInput)
                .autocapitalization(.none)
            SecureField("New Password", text: $viewModel.newPasswordInput)
            Button("Reset Password") { Task { await viewModel.resetPassword() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.resetTokenInput.isEmpty || viewModel
                    .newPasswordInput.isEmpty)
            Button("Change Password (authenticated)") { Task { await viewModel.changePassword() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.passwordInput.isEmpty || viewModel
                    .newPasswordInput.isEmpty)
        }
    }
}

struct UsernameAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Username") {
            TextField("Username", text: $viewModel.usernameInput)
                .autocapitalization(.none)
            SecureField("Password", text: $viewModel.passwordInput)
            Button("Check Availability") { Task { await viewModel.checkUsernameAvailability() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.usernameInput.isEmpty)
            Button("Sign In with Username") { Task { await viewModel.signInWithUsername() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.usernameInput.isEmpty || viewModel.passwordInput
                    .isEmpty)
        }
    }
}

struct MagicLinkAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Magic Link") {
            TextField("Email", text: $viewModel.emailInput)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            Button("Send Magic Link") { Task { await viewModel.requestMagicLink() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty)
            TextField("Token (from link)", text: $viewModel.tokenInput)
                .autocapitalization(.none)
            Button("Verify Magic Link") { Task { await viewModel.verifyMagicLink() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.tokenInput.isEmpty)
        }
    }
}

struct EmailOTPAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Email OTP") {
            TextField("Email", text: $viewModel.emailInput)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            Button("Request OTP") { Task { await viewModel.requestEmailOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty)
            TextField("OTP Code", text: $viewModel.otpInput)
                .keyboardType(.numberPad)
            Button("Sign In with OTP") { Task { await viewModel.signInWithEmailOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty || viewModel.otpInput
                    .isEmpty)
            Button("Verify OTP (email verification)") { Task { await viewModel.verifyEmailOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.emailInput.isEmpty || viewModel.otpInput
                    .isEmpty)
        }
    }
}

struct PhoneOTPAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Phone OTP") {
            TextField("Phone Number (+1…)", text: $viewModel.otpInput)
                .keyboardType(.phonePad)
            Button("Request Phone OTP") { Task { await viewModel.requestPhoneOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.otpInput.isEmpty)
            TextField("Code", text: $viewModel.tokenInput)
                .keyboardType(.numberPad)
            Button("Verify Phone Number") { Task { await viewModel.verifyPhoneOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.otpInput.isEmpty || viewModel.tokenInput
                    .isEmpty)
            Button("Sign In with Phone OTP") { Task { await viewModel.signInWithPhoneOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.otpInput.isEmpty || viewModel.tokenInput
                    .isEmpty)
        }
    }
}

struct TwoFactorAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Two Factor") {
            SecureField("Current Password", text: $viewModel.passwordInput)
            Button("Enable 2FA") { Task { await viewModel.enableTwoFactor() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.passwordInput.isEmpty)
            if let secret = viewModel.twoFactorSecret {
                LabeledContent("TOTP URI") {
                    Text(secret)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .lineLimit(3)
                }
            }
            Button("Send 2FA OTP") { Task { await viewModel.sendTwoFactorOTP() } }
                .disabled(viewModel.isPerformingAuthAction)
            TextField("TOTP Code", text: $viewModel.twoFactorTOTPInput)
                .keyboardType(.numberPad)
            Button("Verify TOTP") { Task { await viewModel.verifyTwoFactorTOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.twoFactorTOTPInput.isEmpty)
            TextField("OTP Code", text: $viewModel.twoFactorOTPInput)
                .keyboardType(.numberPad)
            Button("Verify 2FA OTP") { Task { await viewModel.verifyTwoFactorOTP() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.twoFactorOTPInput.isEmpty)
            TextField("Recovery Code", text: $viewModel.twoFactorRecoveryInput)
                .autocapitalization(.none)
            Button("Use Recovery Code") { Task { await viewModel.verifyTwoFactorRecovery() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.twoFactorRecoveryInput.isEmpty)
            SecureField("Password (backup codes)", text: $viewModel.twoFactorPassword)
            Button("Generate Backup Codes") { Task { await viewModel.generateBackupCodes() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.twoFactorPassword.isEmpty)
            if !viewModel.backupCodes.isEmpty {
                ForEach(viewModel.backupCodes, id: \.self) { code in
                    Text(code).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
        }
    }
}

struct EmailVerificationAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Email Verification") {
            Button("Send Verification Email") { Task { await viewModel.sendVerificationEmail() } }
                .disabled(viewModel.isPerformingAuthAction)
            TextField("Verification Token", text: $viewModel.tokenInput)
                .autocapitalization(.none)
            Button("Verify Email") { Task { await viewModel.verifyEmail() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.tokenInput.isEmpty)
            TextField("New Email Address", text: $viewModel.newEmailInput)
                .keyboardType(.emailAddress)
                .autocapitalization(.none)
            Button("Request Email Change") { Task { await viewModel.changeEmail() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.newEmailInput.isEmpty)
        }
    }
}

struct ProfileAuthSection: View {
    @Bindable var viewModel: AuthViewModel

    var body: some View {
        Section("Profile") {
            TextField("Display Name", text: $viewModel.nameInput)
                .autocapitalization(.words)
            Button("Update Name") { Task { await viewModel.updateDisplayName() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.nameInput.isEmpty || viewModel.session == nil)
        }
    }
}

struct SessionManagementAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("Session Management") {
            Button("Load Sessions") { Task { await viewModel.loadSessions() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            if !viewModel.sessionList.isEmpty {
                ForEach(viewModel.sessionList, id: \.id) { entry in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.id).font(.caption.monospaced()).lineLimit(1)
                        if let ua = entry.userAgent {
                            Text(ua).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }
                }
            }
            Button("Load Device Sessions") { Task { await viewModel.loadDeviceSessions() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            if !viewModel.deviceSessions.isEmpty {
                ForEach(viewModel.deviceSessions, id: \.session.id) { ds in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ds.session.id).font(.caption.monospaced()).lineLimit(1)
                        Text(ds.user.email ?? ds.user.name ?? "Unknown device")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
            Button("Revoke Other Sessions") { Task { await viewModel.revokeOtherSessions() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            Button("Revoke All Sessions", role: .destructive) { Task { await viewModel.revokeSessions() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            Button("Delete Account", role: .destructive) { Task { await viewModel.deleteUser() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
        }
    }
}

struct LinkedAccountsAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("Linked Accounts") {
            Button("Load Linked Accounts") { Task { await viewModel.loadLinkedAccounts() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            if !viewModel.linkedAccounts.isEmpty {
                ForEach(viewModel.linkedAccounts, id: \.id) { account in
                    LabeledContent(account.providerId, value: account.accountId)
                }
            }
        }
    }
}

struct PasskeysAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("Passkeys") {
            Button("Load Passkeys") { Task { await viewModel.loadPasskeys() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            if !viewModel.passkeys.isEmpty {
                ForEach(viewModel.passkeys, id: \.id) { passkey in
                    LabeledContent(passkey.name ?? "Unnamed") {
                        Text(passkey.id.prefix(12) + "…")
                            .font(.caption.monospaced())
                    }
                }
            }
        }
    }
}

struct JWTAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("JWT") {
            Button("Get Session JWT") { Task { await viewModel.loadJWT() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
            if let jwt = viewModel.jwtToken {
                Text(String(jwt.prefix(64)) + "…")
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(3)
            }
        }
    }
}

struct AnonymousAuthSection: View {
    let viewModel: AuthViewModel

    var body: some View {
        Section("Anonymous") {
            Button("Sign In Anonymously") { Task { await viewModel.signInAnonymously() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session != nil)
            Button("Delete Anonymous User", role: .destructive) { Task { await viewModel.deleteAnonymousUser() } }
                .disabled(viewModel.isPerformingAuthAction || viewModel.session == nil)
        }
    }
}
