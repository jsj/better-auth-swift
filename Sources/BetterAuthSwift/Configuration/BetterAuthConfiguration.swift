import Foundation

public struct BetterAuthConfiguration: Sendable {
    public let baseURL: URL
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
                authThrottlePolicy: AuthThrottlePolicy? = nil,
                callbackURLSchemes: Set<String>? = nil,
                retryPolicy: RetryPolicy? = nil,
                requestOrigin: String? = nil,
                logger: BetterAuthLogger? = nil)
    {
        self.baseURL = baseURL
        self.storage = storage
        self.endpoints = endpoints
        let resolvedAuth = Auth(clockSkew: clockSkew ?? auth.clockSkew,
                                autoRefreshToken: autoRefreshToken ?? auth.autoRefreshToken,
                                throttlePolicy: authThrottlePolicy ?? auth.throttlePolicy,
                                callbackURLSchemes: callbackURLSchemes ?? auth.callbackURLSchemes)
        self.auth = resolvedAuth
        self.networking = Networking(retryPolicy: retryPolicy ?? networking.retryPolicy,
                                     requestOrigin: requestOrigin ?? networking.requestOrigin,
                                     timeoutInterval: networking.timeoutInterval)
        self.logger = logger
    }
}

public extension BetterAuthConfiguration {
    var clockSkew: TimeInterval {
        auth.clockSkew
    }

    var autoRefreshToken: Bool {
        auth.autoRefreshToken
    }

    var retryPolicy: RetryPolicy {
        networking.retryPolicy
    }

    var requestOrigin: String? {
        networking.requestOrigin
    }

    var timeoutInterval: TimeInterval {
        networking.timeoutInterval
    }

    struct Auth: Sendable {
        public let clockSkew: TimeInterval
        public let autoRefreshToken: Bool
        public let throttlePolicy: AuthThrottlePolicy?
        public let callbackURLSchemes: Set<String>

        public init(clockSkew: TimeInterval = 60,
                    autoRefreshToken: Bool = true,
                    throttlePolicy: AuthThrottlePolicy? = nil,
                    callbackURLSchemes: Set<String> = [])
        {
            self.clockSkew = clockSkew
            self.autoRefreshToken = autoRefreshToken
            self.throttlePolicy = throttlePolicy
            self.callbackURLSchemes = Set(callbackURLSchemes.map { $0.lowercased() })
        }
    }

    struct AuthThrottlePolicy: Sendable, Equatable {
        public let minimumInterval: TimeInterval

        public init(minimumInterval: TimeInterval = 1) {
            self.minimumInterval = minimumInterval
        }
    }

    struct Networking: Sendable {
        public let retryPolicy: RetryPolicy
        public let requestOrigin: String?
        public let timeoutInterval: TimeInterval

        public init(retryPolicy: RetryPolicy = .default,
                    requestOrigin: String? = nil,
                    timeoutInterval: TimeInterval = 15)
        {
            self.retryPolicy = retryPolicy
            self.requestOrigin = requestOrigin
            self.timeoutInterval = timeoutInterval
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
        public let auth: AuthEndpoints
        public let user: UserEndpoints
        public let session: SessionEndpoints
        public let oauth: OAuthEndpoints
        public let passkey: PasskeyEndpoints
        public let magicLink: MagicLinkEndpoints
        public let emailOTP: EmailOTPEndpoints
        public let phoneOTP: PhoneOTPEndpoints
        public let twoFactor: TwoFactorEndpoints

        public init(auth: AuthEndpoints = .init(),
                    user: UserEndpoints = .init(),
                    session: SessionEndpoints = .init(),
                    oauth: OAuthEndpoints = .init(),
                    passkey: PasskeyEndpoints = .init(),
                    magicLink: MagicLinkEndpoints = .init(),
                    emailOTP: EmailOTPEndpoints = .init(),
                    phoneOTP: PhoneOTPEndpoints = .init(),
                    twoFactor: TwoFactorEndpoints = .init())
        {
            self.auth = auth
            self.user = user
            self.session = session
            self.oauth = oauth
            self.passkey = passkey
            self.magicLink = magicLink
            self.emailOTP = emailOTP
            self.phoneOTP = phoneOTP
            self.twoFactor = twoFactor
        }

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
                    genericOAuthCallbackPath: String = "/api/auth/oauth2/callback/{providerId}",
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
            self.init(auth: .init(emailSignUpPath: emailSignUpPath,
                                  emailSignInPath: emailSignInPath,
                                  usernameAvailabilityPath: usernameAvailabilityPath,
                                  usernameSignInPath: usernameSignInPath,
                                  nativeAppleSignInPath: nativeAppleSignInPath,
                                  socialSignInPath: socialSignInPath,
                                  anonymousSignInPath: anonymousSignInPath,
                                  forgotPasswordPath: forgotPasswordPath,
                                  resetPasswordPath: resetPasswordPath),
                      user: .init(deleteAnonymousUserPath: deleteAnonymousUserPath,
                                  deleteUserPath: deleteUserPath,
                                  sendVerificationEmailPath: sendVerificationEmailPath,
                                  verifyEmailPath: verifyEmailPath,
                                  changeEmailPath: changeEmailPath,
                                  updateUserPath: updateUserPath,
                                  changePasswordPath: changePasswordPath),
                      session: .init(listSessionsPath: listSessionsPath,
                                     listDeviceSessionsPath: listDeviceSessionsPath,
                                     setActiveDeviceSessionPath: setActiveDeviceSessionPath,
                                     revokeDeviceSessionPath: revokeDeviceSessionPath,
                                     sessionJWTPath: sessionJWTPath,
                                     jwksPath: jwksPath,
                                     revokeSessionPath: revokeSessionPath,
                                     revokeSessionsPath: revokeSessionsPath,
                                     revokeOtherSessionsPath: revokeOtherSessionsPath,
                                     sessionRefreshPath: sessionRefreshPath,
                                     currentSessionPath: currentSessionPath,
                                     signOutPath: signOutPath),
                      oauth: .init(genericOAuthSignInPath: genericOAuthSignInPath,
                                   genericOAuthLinkPath: genericOAuthLinkPath,
                                   genericOAuthCallbackPath: genericOAuthCallbackPath,
                                   listLinkedAccountsPath: listLinkedAccountsPath,
                                   linkSocialAccountPath: linkSocialAccountPath),
                      passkey: .init(registerOptionsPath: passkeyRegisterOptionsPath,
                                     authenticateOptionsPath: passkeyAuthenticateOptionsPath,
                                     registerPath: passkeyRegisterPath,
                                     authenticatePath: passkeyAuthenticatePath,
                                     listPath: listPasskeysPath,
                                     updatePath: updatePasskeyPath,
                                     deletePath: deletePasskeyPath),
                      magicLink: .init(signInPath: magicLinkSignInPath,
                                       verifyPath: magicLinkVerifyPath),
                      emailOTP: .init(requestPath: emailOTPRequestPath,
                                      signInPath: emailOTPSignInPath,
                                      verifyPath: emailOTPVerifyPath),
                      phoneOTP: .init(requestPath: phoneOTPRequestPath,
                                      verifyPath: phoneOTPVerifyPath,
                                      signInPath: phoneOTPSignInPath),
                      twoFactor: .init(enablePath: twoFactorEnablePath,
                                       verifyTOTPPath: twoFactorVerifyTOTPPath,
                                       sendOTPPath: twoFactorSendOTPPath,
                                       verifyOTPPath: twoFactorVerifyOTPPath,
                                       verifyBackupCodePath: twoFactorVerifyBackupCodePath,
                                       generateBackupCodesPath: twoFactorGenerateBackupCodesPath,
                                       disablePath: twoFactorDisablePath))
        }
    }

    struct AuthEndpoints: Sendable {
        public let emailSignUpPath: String
        public let emailSignInPath: String
        public let usernameAvailabilityPath: String
        public let usernameSignInPath: String
        public let nativeAppleSignInPath: String
        public let socialSignInPath: String
        public let anonymousSignInPath: String
        public let forgotPasswordPath: String
        public let resetPasswordPath: String

        public init(emailSignUpPath: String = "/api/auth/email/sign-up",
                    emailSignInPath: String = "/api/auth/email/sign-in",
                    usernameAvailabilityPath: String = "/api/auth/is-username-available",
                    usernameSignInPath: String = "/api/auth/sign-in/username",
                    nativeAppleSignInPath: String = "/api/auth/apple/native",
                    socialSignInPath: String = "/api/auth/sign-in/social",
                    anonymousSignInPath: String = "/api/auth/sign-in/anonymous",
                    forgotPasswordPath: String = "/api/auth/forget-password",
                    resetPasswordPath: String = "/api/auth/reset-password")
        {
            self.emailSignUpPath = emailSignUpPath
            self.emailSignInPath = emailSignInPath
            self.usernameAvailabilityPath = usernameAvailabilityPath
            self.usernameSignInPath = usernameSignInPath
            self.nativeAppleSignInPath = nativeAppleSignInPath
            self.socialSignInPath = socialSignInPath
            self.anonymousSignInPath = anonymousSignInPath
            self.forgotPasswordPath = forgotPasswordPath
            self.resetPasswordPath = resetPasswordPath
        }
    }

    struct UserEndpoints: Sendable {
        public let deleteAnonymousUserPath: String
        public let deleteUserPath: String
        public let sendVerificationEmailPath: String
        public let verifyEmailPath: String
        public let changeEmailPath: String
        public let updateUserPath: String
        public let changePasswordPath: String

        public init(deleteAnonymousUserPath: String = "/api/auth/delete-anonymous-user",
                    deleteUserPath: String = "/api/auth/delete-user",
                    sendVerificationEmailPath: String = "/api/auth/send-verification-email",
                    verifyEmailPath: String = "/api/auth/verify-email",
                    changeEmailPath: String = "/api/auth/change-email",
                    updateUserPath: String = "/api/auth/update-user",
                    changePasswordPath: String = "/api/auth/change-password")
        {
            self.deleteAnonymousUserPath = deleteAnonymousUserPath
            self.deleteUserPath = deleteUserPath
            self.sendVerificationEmailPath = sendVerificationEmailPath
            self.verifyEmailPath = verifyEmailPath
            self.changeEmailPath = changeEmailPath
            self.updateUserPath = updateUserPath
            self.changePasswordPath = changePasswordPath
        }
    }

    struct SessionEndpoints: Sendable {
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

        public init(listSessionsPath: String = "/api/auth/list-sessions",
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

    struct OAuthEndpoints: Sendable {
        public let genericOAuthSignInPath: String
        public let genericOAuthLinkPath: String
        public let genericOAuthCallbackPath: String
        public let listLinkedAccountsPath: String
        public let linkSocialAccountPath: String

        public init(genericOAuthSignInPath: String = "/api/auth/sign-in/oauth2",
                    genericOAuthLinkPath: String = "/api/auth/oauth2/link",
                    genericOAuthCallbackPath: String = "/api/auth/oauth2/callback/{providerId}",
                    listLinkedAccountsPath: String = "/api/auth/list-accounts",
                    linkSocialAccountPath: String = "/api/auth/link-social")
        {
            self.genericOAuthSignInPath = genericOAuthSignInPath
            self.genericOAuthLinkPath = genericOAuthLinkPath
            self.genericOAuthCallbackPath = genericOAuthCallbackPath
            self.listLinkedAccountsPath = listLinkedAccountsPath
            self.linkSocialAccountPath = linkSocialAccountPath
        }
    }

    struct PasskeyEndpoints: Sendable {
        public let registerOptionsPath: String
        public let authenticateOptionsPath: String
        public let registerPath: String
        public let authenticatePath: String
        public let listPath: String
        public let updatePath: String
        public let deletePath: String

        public init(registerOptionsPath: String = "/api/auth/passkey/generate-register-options",
                    authenticateOptionsPath: String = "/api/auth/passkey/generate-authenticate-options",
                    registerPath: String = "/api/auth/passkey/verify-registration",
                    authenticatePath: String = "/api/auth/passkey/verify-authentication",
                    listPath: String = "/api/auth/passkey/list-user-passkeys",
                    updatePath: String = "/api/auth/passkey/update-passkey",
                    deletePath: String = "/api/auth/passkey/delete-passkey")
        {
            self.registerOptionsPath = registerOptionsPath
            self.authenticateOptionsPath = authenticateOptionsPath
            self.registerPath = registerPath
            self.authenticatePath = authenticatePath
            self.listPath = listPath
            self.updatePath = updatePath
            self.deletePath = deletePath
        }
    }

    struct MagicLinkEndpoints: Sendable {
        public let signInPath: String
        public let verifyPath: String

        public init(signInPath: String = "/api/auth/sign-in/magic-link",
                    verifyPath: String = "/api/auth/magic-link/verify")
        {
            self.signInPath = signInPath
            self.verifyPath = verifyPath
        }
    }

    struct EmailOTPEndpoints: Sendable {
        public let requestPath: String
        public let signInPath: String
        public let verifyPath: String

        public init(requestPath: String = "/api/auth/email-otp/send-verification-otp",
                    signInPath: String = "/api/auth/sign-in/email-otp",
                    verifyPath: String = "/api/auth/email-otp/verify-email")
        {
            self.requestPath = requestPath
            self.signInPath = signInPath
            self.verifyPath = verifyPath
        }
    }

    struct PhoneOTPEndpoints: Sendable {
        public let requestPath: String
        public let verifyPath: String
        public let signInPath: String

        public init(requestPath: String = "/api/auth/phone-number/send-otp",
                    verifyPath: String = "/api/auth/phone-number/verify",
                    signInPath: String = "/api/auth/sign-in/phone-number")
        {
            self.requestPath = requestPath
            self.verifyPath = verifyPath
            self.signInPath = signInPath
        }
    }

    struct TwoFactorEndpoints: Sendable {
        public let enablePath: String
        public let verifyTOTPPath: String
        public let sendOTPPath: String
        public let verifyOTPPath: String
        public let verifyBackupCodePath: String
        public let generateBackupCodesPath: String
        public let disablePath: String

        public init(enablePath: String = "/api/auth/two-factor/enable",
                    verifyTOTPPath: String = "/api/auth/two-factor/verify-totp",
                    sendOTPPath: String = "/api/auth/two-factor/send-otp",
                    verifyOTPPath: String = "/api/auth/two-factor/verify-otp",
                    verifyBackupCodePath: String = "/api/auth/two-factor/verify-backup-code",
                    generateBackupCodesPath: String = "/api/auth/two-factor/generate-backup-codes",
                    disablePath: String = "/api/auth/two-factor/disable")
        {
            self.enablePath = enablePath
            self.verifyTOTPPath = verifyTOTPPath
            self.sendOTPPath = sendOTPPath
            self.verifyOTPPath = verifyOTPPath
            self.verifyBackupCodePath = verifyBackupCodePath
            self.generateBackupCodesPath = generateBackupCodesPath
            self.disablePath = disablePath
        }
    }
}
