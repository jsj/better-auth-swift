import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Passkey

    @discardableResult
    func passkeyRegistrationOptions(_ payload: PasskeyRegistrationOptionsRequest = .init()) async throws
        -> PasskeyRegistrationOptions
    {
        try await performThrowing {
            let options = try await auth.passkeyRegistrationOptions(payload)
            statusMessage = "Passkey registration options fetched"
            return options
        }
    }

    @discardableResult
    func passkeyAuthenticateOptions() async throws -> PasskeyAuthenticationOptions {
        try await performThrowing {
            let options = try await auth.passkeyAuthenticateOptions()
            statusMessage = "Passkey authentication options fetched"
            return options
        }
    }

    func registerPasskey(_ payload: PasskeyRegistrationRequest) async {
        await perform {
            _ = try await auth.registerPasskey(payload)
            statusMessage = "Passkey registered"
        }
    }

    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async {
        await perform {
            _ = try await auth.authenticateWithPasskey(payload)
            statusMessage = "Signed in with passkey"
        }
    }

    @discardableResult
    func listPasskeys() async throws -> [Passkey] {
        try await performThrowing {
            let passkeys = try await auth.listPasskeys()
            statusMessage = "Passkeys loaded"
            return passkeys
        }
    }

    func updatePasskey(_ payload: UpdatePasskeyRequest) async {
        await perform {
            _ = try await auth.updatePasskey(payload)
            statusMessage = "Passkey updated"
        }
    }

    func deletePasskey(_ payload: DeletePasskeyRequest) async {
        await perform {
            _ = try await auth.deletePasskey(payload)
            statusMessage = "Passkey deleted"
        }
    }

    // MARK: - Email Verification

    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init()) async {
        await perform {
            _ = try await auth.sendVerificationEmail(payload)
            statusMessage = "Verification email sent"
        }
    }

    func verifyEmail(_ payload: VerifyEmailRequest) async {
        await perform {
            _ = try await auth.verifyEmail(payload)
            statusMessage = "Email verified"
        }
    }

    func changeEmail(_ payload: ChangeEmailRequest) async {
        await perform {
            _ = try await auth.changeEmail(payload)
            statusMessage = "Change email requested"
        }
    }

    // MARK: - Account Management

    func updateUser(_ payload: UpdateUserRequest) async {
        await perform {
            _ = try await auth.updateUser(payload)
            statusMessage = "Profile updated"
        }
    }

    // MARK: - Linked Accounts

    @discardableResult
    func listLinkedAccounts() async throws -> [LinkedAccount] {
        try await performThrowing {
            let accounts = try await auth.listLinkedAccounts()
            statusMessage = "Linked accounts loaded"
            return accounts
        }
    }

    @discardableResult
    func linkSocialAccount(_ payload: LinkSocialAccountRequest) async throws -> LinkSocialAccountResponse {
        try await performThrowing {
            let response = try await auth.linkSocialAccount(payload)
            statusMessage = "Social account linked"
            return response
        }
    }

    // MARK: - Sessions

    @discardableResult
    func listSessions() async throws -> [BetterAuthSessionListEntry] {
        try await performThrowing {
            let sessions = try await auth.listSessions()
            statusMessage = "Sessions loaded"
            return sessions
        }
    }

    @discardableResult
    func listDeviceSessions() async throws -> [BetterAuthDeviceSession] {
        try await performThrowing {
            let sessions = try await auth.listDeviceSessions()
            statusMessage = "Device sessions loaded"
            return sessions
        }
    }

    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest) async {
        await perform {
            _ = try await auth.setActiveDeviceSession(payload)
            statusMessage = "Active session switched"
        }
    }

    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest) async {
        await perform {
            _ = try await auth.revokeDeviceSession(payload)
            statusMessage = "Device session revoked"
        }
    }

    func revokeSession(token: String) async {
        await perform {
            _ = try await auth.revokeSession(token: token)
            statusMessage = "Session revoked"
        }
    }

    func revokeSessions() async {
        await perform {
            _ = try await auth.revokeSessions()
            statusMessage = "All sessions revoked"
        }
    }

    func revokeOtherSessions() async {
        await perform {
            _ = try await auth.revokeOtherSessions()
            statusMessage = "Other sessions revoked"
        }
    }

    // MARK: - JWT

    @discardableResult
    func getSessionJWT() async throws -> BetterAuthJWT {
        try await performThrowing {
            let jwt = try await auth.getSessionJWT()
            statusMessage = "JWT fetched"
            return jwt
        }
    }

    @discardableResult
    func getJWKS() async throws -> BetterAuthJWKS {
        try await performThrowing {
            let jwks = try await auth.getJWKS()
            statusMessage = "JWKS fetched"
            return jwks
        }
    }
}
