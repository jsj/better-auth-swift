import Foundation

public struct BetterAuthConfiguration: Sendable {
    public let baseURL: URL
    public let clockSkew: TimeInterval
    public let storage: SessionStorage
    public let endpoints: Endpoints
    public let auth: Auth
    public let networking: Networking
    public let logger: BetterAuthLogger?

    public init(baseURL: URL,
                storage: SessionStorage = .init(),
                endpoints: Endpoints = .init(),
                auth: Auth = .init(),
                networking: Networking = .init(),
                clockSkew: TimeInterval? = nil,
                autoRefreshToken: Bool? = nil,
                retryPolicy: RetryPolicy? = nil,
                requestOrigin: String? = nil,
                logger: BetterAuthLogger? = nil)
    {
        self.baseURL = baseURL
        self.storage = storage
        self.endpoints = endpoints
        let resolvedAuth = Auth(clockSkew: clockSkew ?? auth.clockSkew,
                                autoRefreshToken: autoRefreshToken ?? auth.autoRefreshToken)
        self.auth = resolvedAuth
        self.clockSkew = resolvedAuth.clockSkew
        self.networking = Networking(retryPolicy: retryPolicy ?? networking.retryPolicy,
                                     requestOrigin: requestOrigin ?? networking.requestOrigin)
        self.logger = logger
    }
}

public extension BetterAuthConfiguration {
    var autoRefreshToken: Bool { auth.autoRefreshToken }
    var retryPolicy: RetryPolicy { networking.retryPolicy }
    var requestOrigin: String? { networking.requestOrigin }

    struct Auth: Sendable {
        public let clockSkew: TimeInterval
        public let autoRefreshToken: Bool

        public init(clockSkew: TimeInterval = 60,
                    autoRefreshToken: Bool = true)
        {
            self.clockSkew = clockSkew
            self.autoRefreshToken = autoRefreshToken
        }
    }

    struct Networking: Sendable {
        public let retryPolicy: RetryPolicy
        public let requestOrigin: String?

        public init(retryPolicy: RetryPolicy = .default,
                    requestOrigin: String? = nil)
        {
            self.retryPolicy = retryPolicy
            self.requestOrigin = requestOrigin
        }
    }

    struct SessionStorage: Sendable {
        public let key: String
        public let service: String
        public let accessGroup: String?
        public let accessibility: KeychainSessionStore.Accessibility
        public let synchronizable: Bool

        public init(key: String = "better-auth.session",
                    service: String = "BetterAuth",
                    accessGroup: String? = nil,
                    accessibility: KeychainSessionStore.Accessibility = .afterFirstUnlock,
                    synchronizable: Bool = false)
        {
            self.key = key
            self.service = service
            self.accessGroup = accessGroup
            self.accessibility = accessibility
            self.synchronizable = synchronizable
        }

        public static func shared(key: String = "better-auth.session",
                                  service: String = "BetterAuth",
                                  accessGroup: String,
                                  accessibility: KeychainSessionStore.Accessibility = .afterFirstUnlock,
                                  synchronizable: Bool = false) -> Self
        {
            .init(key: key,
                  service: service,
                  accessGroup: accessGroup,
                  accessibility: accessibility,
                  synchronizable: synchronizable)
        }
    }

    struct Endpoints: Sendable {
        public let emailSignUpPath: String
        public let emailSignInPath: String
        public let usernameAvailabilityPath: String
        public let usernameSignInPath: String
        public let nativeAppleSignInPath: String
        public let socialSignInPath: String
        public let anonymousSignInPath: String
        public let deleteAnonymousUserPath: String
        public let deleteUserPath: String
        public let genericOAuthSignInPath: String
        public let genericOAuthLinkPath: String
        public let listLinkedAccountsPath: String
        public let linkSocialAccountPath: String
        public let passkeyRegisterOptionsPath: String
        public let passkeyAuthenticateOptionsPath: String
        public let passkeyRegisterPath: String
        public let passkeyAuthenticatePath: String
        public let listPasskeysPath: String
        public let updatePasskeyPath: String
        public let deletePasskeyPath: String
        public let magicLinkSignInPath: String
        public let magicLinkVerifyPath: String
        public let emailOTPRequestPath: String
        public let emailOTPSignInPath: String
        public let emailOTPVerifyPath: String
        public let phoneOTPRequestPath: String
        public let phoneOTPVerifyPath: String
        public let phoneOTPSignInPath: String
        public let twoFactorEnablePath: String
        public let twoFactorVerifyTOTPPath: String
        public let twoFactorSendOTPPath: String
        public let twoFactorVerifyOTPPath: String
        public let twoFactorVerifyBackupCodePath: String
        public let twoFactorGenerateBackupCodesPath: String
        public let twoFactorDisablePath: String
        public let forgotPasswordPath: String
        public let resetPasswordPath: String
        public let sendVerificationEmailPath: String
        public let verifyEmailPath: String
        public let changeEmailPath: String
        public let updateUserPath: String
        public let changePasswordPath: String
        public let listSessionsPath: String
        public let listDeviceSessionsPath: String
        public let setActiveDeviceSessionPath: String
        public let revokeDeviceSessionPath: String
        public let sessionJWTPath: String
        public let jwksPath: String
        public let revokeSessionPath: String
        public let revokeSessionsPath: String
        public let revokeOtherSessionsPath: String
        public let sessionRefreshPath: String
        public let currentSessionPath: String
        public let signOutPath: String

        public init(emailSignUpPath: String = "/api/auth/email/sign-up",
                    emailSignInPath: String = "/api/auth/email/sign-in",
                    usernameAvailabilityPath: String = "/api/auth/is-username-available",
                    usernameSignInPath: String = "/api/auth/sign-in/username",
                    nativeAppleSignInPath: String = "/api/auth/apple/native",
                    socialSignInPath: String = "/api/auth/sign-in/social",
                    anonymousSignInPath: String = "/api/auth/sign-in/anonymous",
                    deleteAnonymousUserPath: String = "/api/auth/delete-anonymous-user",
                    deleteUserPath: String = "/api/auth/delete-user",
                    genericOAuthSignInPath: String = "/api/auth/sign-in/oauth2",
                    genericOAuthLinkPath: String = "/api/auth/oauth2/link",
                    listLinkedAccountsPath: String = "/api/auth/list-accounts",
                    linkSocialAccountPath: String = "/api/auth/link-social",
                    passkeyRegisterOptionsPath: String = "/api/auth/passkey/generate-register-options",
                    passkeyAuthenticateOptionsPath: String = "/api/auth/passkey/generate-authenticate-options",
                    passkeyRegisterPath: String = "/api/auth/passkey/verify-registration",
                    passkeyAuthenticatePath: String = "/api/auth/passkey/verify-authentication",
                    listPasskeysPath: String = "/api/auth/passkey/list-user-passkeys",
                    updatePasskeyPath: String = "/api/auth/passkey/update-passkey",
                    deletePasskeyPath: String = "/api/auth/passkey/delete-passkey",
                    magicLinkSignInPath: String = "/api/auth/sign-in/magic-link",
                    magicLinkVerifyPath: String = "/api/auth/magic-link/verify",
                    emailOTPRequestPath: String = "/api/auth/email-otp/send-verification-otp",
                    emailOTPSignInPath: String = "/api/auth/sign-in/email-otp",
                    emailOTPVerifyPath: String = "/api/auth/email-otp/verify-email",
                    phoneOTPRequestPath: String = "/api/auth/phone-number/send-otp",
                    phoneOTPVerifyPath: String = "/api/auth/phone-number/verify",
                    phoneOTPSignInPath: String = "/api/auth/sign-in/phone-number",
                    twoFactorEnablePath: String = "/api/auth/two-factor/enable",
                    twoFactorVerifyTOTPPath: String = "/api/auth/two-factor/verify-totp",
                    twoFactorSendOTPPath: String = "/api/auth/two-factor/send-otp",
                    twoFactorVerifyOTPPath: String = "/api/auth/two-factor/verify-otp",
                    twoFactorVerifyBackupCodePath: String = "/api/auth/two-factor/verify-backup-code",
                    twoFactorGenerateBackupCodesPath: String = "/api/auth/two-factor/generate-backup-codes",
                    twoFactorDisablePath: String = "/api/auth/two-factor/disable",
                    forgotPasswordPath: String = "/api/auth/forget-password",
                    resetPasswordPath: String = "/api/auth/reset-password",
                    sendVerificationEmailPath: String = "/api/auth/send-verification-email",
                    verifyEmailPath: String = "/api/auth/verify-email",
                    changeEmailPath: String = "/api/auth/change-email",
                    updateUserPath: String = "/api/auth/update-user",
                    changePasswordPath: String = "/api/auth/change-password",
                    listSessionsPath: String = "/api/auth/list-sessions",
                    listDeviceSessionsPath: String = "/api/auth/multi-session/list-device-sessions",
                    setActiveDeviceSessionPath: String = "/api/auth/multi-session/set-active",
                    revokeDeviceSessionPath: String = "/api/auth/multi-session/revoke",
                    sessionJWTPath: String = "/api/auth/token",
                    jwksPath: String = "/api/auth/jwks",
                    revokeSessionPath: String = "/api/auth/revoke-session",
                    revokeSessionsPath: String = "/api/auth/revoke-sessions",
                    revokeOtherSessionsPath: String = "/api/auth/revoke-other-sessions",
                    sessionRefreshPath: String = "/api/auth/get-session",
                    currentSessionPath: String = "/api/auth/get-session",
                    signOutPath: String = "/api/auth/sign-out")
        {
            self.emailSignUpPath = emailSignUpPath
            self.emailSignInPath = emailSignInPath
            self.usernameAvailabilityPath = usernameAvailabilityPath
            self.usernameSignInPath = usernameSignInPath
            self.nativeAppleSignInPath = nativeAppleSignInPath
            self.socialSignInPath = socialSignInPath
            self.anonymousSignInPath = anonymousSignInPath
            self.deleteAnonymousUserPath = deleteAnonymousUserPath
            self.deleteUserPath = deleteUserPath
            self.genericOAuthSignInPath = genericOAuthSignInPath
            self.genericOAuthLinkPath = genericOAuthLinkPath
            self.listLinkedAccountsPath = listLinkedAccountsPath
            self.linkSocialAccountPath = linkSocialAccountPath
            self.passkeyRegisterOptionsPath = passkeyRegisterOptionsPath
            self.passkeyAuthenticateOptionsPath = passkeyAuthenticateOptionsPath
            self.passkeyRegisterPath = passkeyRegisterPath
            self.passkeyAuthenticatePath = passkeyAuthenticatePath
            self.listPasskeysPath = listPasskeysPath
            self.updatePasskeyPath = updatePasskeyPath
            self.deletePasskeyPath = deletePasskeyPath
            self.magicLinkSignInPath = magicLinkSignInPath
            self.magicLinkVerifyPath = magicLinkVerifyPath
            self.emailOTPRequestPath = emailOTPRequestPath
            self.emailOTPSignInPath = emailOTPSignInPath
            self.emailOTPVerifyPath = emailOTPVerifyPath
            self.phoneOTPRequestPath = phoneOTPRequestPath
            self.phoneOTPVerifyPath = phoneOTPVerifyPath
            self.phoneOTPSignInPath = phoneOTPSignInPath
            self.twoFactorEnablePath = twoFactorEnablePath
            self.twoFactorVerifyTOTPPath = twoFactorVerifyTOTPPath
            self.twoFactorSendOTPPath = twoFactorSendOTPPath
            self.twoFactorVerifyOTPPath = twoFactorVerifyOTPPath
            self.twoFactorVerifyBackupCodePath = twoFactorVerifyBackupCodePath
            self.twoFactorGenerateBackupCodesPath = twoFactorGenerateBackupCodesPath
            self.twoFactorDisablePath = twoFactorDisablePath
            self.forgotPasswordPath = forgotPasswordPath
            self.resetPasswordPath = resetPasswordPath
            self.sendVerificationEmailPath = sendVerificationEmailPath
            self.verifyEmailPath = verifyEmailPath
            self.changeEmailPath = changeEmailPath
            self.updateUserPath = updateUserPath
            self.changePasswordPath = changePasswordPath
            self.listSessionsPath = listSessionsPath
            self.listDeviceSessionsPath = listDeviceSessionsPath
            self.setActiveDeviceSessionPath = setActiveDeviceSessionPath
            self.revokeDeviceSessionPath = revokeDeviceSessionPath
            self.sessionJWTPath = sessionJWTPath
            self.jwksPath = jwksPath
            self.revokeSessionPath = revokeSessionPath
            self.revokeSessionsPath = revokeSessionsPath
            self.revokeOtherSessionsPath = revokeOtherSessionsPath
            self.sessionRefreshPath = sessionRefreshPath
            self.currentSessionPath = currentSessionPath
            self.signOutPath = signOutPath
        }
    }
}
