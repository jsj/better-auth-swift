import Foundation

public struct MagicLinkRequest: Codable, Sendable, Equatable {
    public let email: String
    public let name: String?
    public let callbackURL: String?
    public let newUserCallbackURL: String?
    public let errorCallbackURL: String?
    public let metadata: [String: String]?

    public init(email: String,
                name: String? = nil,
                callbackURL: String? = nil,
                newUserCallbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                metadata: [String: String]? = nil)
    {
        self.email = email
        self.name = name
        self.callbackURL = callbackURL
        self.newUserCallbackURL = newUserCallbackURL
        self.errorCallbackURL = errorCallbackURL
        self.metadata = metadata
    }
}

public struct MagicLinkVerifyRequest: Codable, Sendable, Equatable {
    public let token: String
    public let callbackURL: String?
    public let newUserCallbackURL: String?
    public let errorCallbackURL: String?

    public init(token: String,
                callbackURL: String? = nil,
                newUserCallbackURL: String? = nil,
                errorCallbackURL: String? = nil)
    {
        self.token = token
        self.callbackURL = callbackURL
        self.newUserCallbackURL = newUserCallbackURL
        self.errorCallbackURL = errorCallbackURL
    }
}

public enum EmailOTPRequestType: String, Codable, Sendable, Equatable {
    case signIn = "sign-in"
    case emailVerification = "email-verification"
}

public struct EmailOTPRequest: Codable, Sendable, Equatable {
    public let email: String
    public let type: EmailOTPRequestType

    public init(email: String, type: EmailOTPRequestType) {
        self.email = email
        self.type = type
    }
}

public struct EmailOTPRequestResponse: Codable, Sendable, Equatable {
    public let success: Bool

    public init(success: Bool) {
        self.success = success
    }
}

public struct EmailOTPSignInRequest: Codable, Sendable, Equatable {
    public let email: String
    public let otp: String
    public let name: String?
    public let image: String?

    public init(email: String, otp: String, name: String? = nil, image: String? = nil) {
        self.email = email
        self.otp = otp
        self.name = name
        self.image = image
    }
}

public struct EmailOTPVerifyRequest: Codable, Sendable, Equatable {
    public let email: String
    public let otp: String

    public init(email: String, otp: String) {
        self.email = email
        self.otp = otp
    }
}

public struct PhoneOTPRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String

    public init(phoneNumber: String) {
        self.phoneNumber = phoneNumber
    }
}

public struct PhoneOTPRequestResponse: Codable, Sendable, Equatable {
    public let message: String?
    public let success: Bool?
    public let status: Bool?

    public init(message: String? = nil, success: Bool? = nil, status: Bool? = nil) {
        self.message = message
        self.success = success
        self.status = status
    }
}

public struct PhoneOTPVerifyRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String
    public let code: String
    public let disableSession: Bool?
    public let updatePhoneNumber: Bool?

    public init(phoneNumber: String,
                code: String,
                disableSession: Bool? = nil,
                updatePhoneNumber: Bool? = nil)
    {
        self.phoneNumber = phoneNumber
        self.code = code
        self.disableSession = disableSession
        self.updatePhoneNumber = updatePhoneNumber
    }
}

public struct PhoneOTPVerifyResponse: Codable, Sendable, Equatable {
    public let status: Bool
    public let token: String?
    public let user: BetterAuthSession.User?

    public init(status: Bool, token: String? = nil, user: BetterAuthSession.User? = nil) {
        self.status = status
        self.token = token
        self.user = user
    }
}

public struct PhoneOTPSignInRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String
    public let password: String
    public let rememberMe: Bool?

    public init(phoneNumber: String, password: String, rememberMe: Bool? = nil) {
        self.phoneNumber = phoneNumber
        self.password = password
        self.rememberMe = rememberMe
    }
}

public struct TwoFactorEnableRequest: Codable, Sendable, Equatable {
    public let password: String
    public let issuer: String?

    public init(password: String, issuer: String? = nil) {
        self.password = password
        self.issuer = issuer
    }
}

public struct TwoFactorEnableResponse: Codable, Sendable, Equatable {
    public let totpURI: String
    public let backupCodes: [String]

    public init(totpURI: String, backupCodes: [String]) {
        self.totpURI = totpURI
        self.backupCodes = backupCodes
    }
}

public struct TwoFactorDisableRequest: Codable, Sendable, Equatable {
    public let password: String

    public init(password: String) {
        self.password = password
    }
}

public struct TwoFactorVerifyTOTPRequest: Codable, Sendable, Equatable {
    public let code: String
    public let trustDevice: Bool?

    public init(code: String, trustDevice: Bool? = nil) {
        self.code = code
        self.trustDevice = trustDevice
    }
}

public struct TwoFactorSendOTPRequest: Codable, Sendable, Equatable {
    public let trustDevice: Bool?

    public init(trustDevice: Bool? = nil) {
        self.trustDevice = trustDevice
    }
}

public struct TwoFactorVerifyOTPRequest: Codable, Sendable, Equatable {
    public let code: String
    public let trustDevice: Bool?

    public init(code: String, trustDevice: Bool? = nil) {
        self.code = code
        self.trustDevice = trustDevice
    }
}

public struct TwoFactorVerifyBackupCodeRequest: Codable, Sendable, Equatable {
    public let code: String
    public let trustDevice: Bool?
    public let disableSession: Bool?

    public init(code: String, trustDevice: Bool? = nil, disableSession: Bool? = nil) {
        self.code = code
        self.trustDevice = trustDevice
        self.disableSession = disableSession
    }
}

public struct TwoFactorChallengeStatusResponse: Codable, Sendable, Equatable {
    public let status: Bool

    public init(status: Bool) {
        self.status = status
    }
}

public struct TwoFactorSessionResponse: Codable, Sendable, Equatable {
    public let token: String
    public let user: TwoFactorUser

    public init(token: String, user: TwoFactorUser) {
        self.token = token
        self.user = user
    }
}

public struct TwoFactorGenerateBackupCodesResponse: Codable, Sendable, Equatable {
    public let status: Bool
    public let backupCodes: [String]

    public init(status: Bool, backupCodes: [String]) {
        self.status = status
        self.backupCodes = backupCodes
    }
}

public struct TwoFactorUser: Codable, Sendable, Equatable {
    public let id: String
    public let email: String?
    public let name: String?
    public let username: String?
    public let displayUsername: String?
    public let twoFactorEnabled: Bool

    public init(id: String,
                email: String? = nil,
                name: String? = nil,
                username: String? = nil,
                displayUsername: String? = nil,
                twoFactorEnabled: Bool)
    {
        self.id = id
        self.email = email
        self.name = name
        self.username = username
        self.displayUsername = displayUsername
        self.twoFactorEnabled = twoFactorEnabled
    }
}

public enum EmailOTPVerifyResult: Codable, Sendable, Equatable {
    case verified(BetterAuthSession.User)
    case signedIn(BetterAuthSession)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self = .signedIn(session)
            return
        }
        if let response = try? container.decode(SocialSignInTransportResponse.self),
           let session = response.materializedSession
        {
            self = .signedIn(session)
            return
        }
        let response = try container.decode(EmailOTPVerifyResponse.self)
        if let session = response.session {
            self = .signedIn(session)
        } else {
            self = .verified(response.user)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .verified(user):
            try container.encode(EmailOTPVerifyResponse(status: true, session: nil, user: user))

        case let .signedIn(session):
            try container.encode(EmailOTPVerifyResponse(status: true, session: session, user: session.user))
        }
    }
}

public enum MagicLinkVerificationResult: Codable, Sendable, Equatable {
    case signedIn(BetterAuthSession)
    case failure(MagicLinkFailure)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self = .signedIn(session)
            return
        }
        if let response = try? container.decode(SocialSignInTransportResponse.self),
           let session = response.materializedSession
        {
            self = .signedIn(session)
            return
        }

        self = try .failure(container.decode(MagicLinkFailure.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .signedIn(session):
            try container.encode(session)

        case let .failure(failure):
            try container.encode(failure)
        }
    }
}

public struct MagicLinkFailure: Codable, Sendable, Equatable {
    public let error: String
    public let status: Int?
    public let redirectURL: String?

    public init(error: String, status: Int? = nil, redirectURL: String? = nil) {
        self.error = error
        self.status = status
        self.redirectURL = redirectURL
    }
}

public struct EmailSignUpRequest: Codable, Sendable, Equatable {
    public let email: String
    public let password: String
    public let name: String
    public let username: String?
    public let displayUsername: String?

    public init(email: String,
                password: String,
                name: String,
                username: String? = nil,
                displayUsername: String? = nil)
    {
        self.email = email
        self.password = password
        self.name = name
        self.username = username
        self.displayUsername = displayUsername
    }
}

public enum EmailSignUpResult: Codable, Sendable, Equatable {
    case signedIn(BetterAuthSession)
    case verificationHeld(VerificationHeldEmailSignUp)
    case signedUp(SuccessfulEmailSignUp)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self = .signedIn(session)
            return
        }

        let held = try container.decode(VerificationHeldEmailSignUp.self)
        self = held
            .requiresVerification ? .verificationHeld(held) :
            .signedUp(.init(requiresVerification: held.requiresVerification,
                            user: held.user))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .signedIn(session):
            try container.encode(session)

        case let .signedUp(signedUp):
            try container.encode(signedUp)

        case let .verificationHeld(held):
            try container.encode(held)
        }
    }
}

public struct SuccessfulEmailSignUp: Codable, Sendable, Equatable {
    public let requiresVerification: Bool
    public let user: BetterAuthSession.User?

    public init(requiresVerification: Bool = false, user: BetterAuthSession.User? = nil) {
        self.requiresVerification = requiresVerification
        self.user = user
    }
}

public struct VerificationHeldEmailSignUp: Codable, Sendable, Equatable {
    public let requiresVerification: Bool
    public let user: BetterAuthSession.User?

    public init(requiresVerification: Bool = true, user: BetterAuthSession.User? = nil) {
        self.requiresVerification = requiresVerification
        self.user = user
    }
}

public struct EmailSignInRequest: Codable, Sendable, Equatable {
    public let email: String
    public let password: String

    public init(email: String, password: String) {
        self.email = email
        self.password = password
    }
}

public struct UsernameAvailabilityRequest: Codable, Sendable, Equatable {
    public let username: String

    public init(username: String) {
        self.username = username
    }
}

public struct UsernameAvailabilityResponse: Codable, Sendable, Equatable {
    public let available: Bool

    public init(available: Bool) {
        self.available = available
    }
}

public struct UsernameSignInRequest: Codable, Sendable, Equatable {
    public let username: String
    public let password: String

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

public struct UpdateUserRequest: Codable, Sendable, Equatable {
    public let name: String?
    public let image: String?
    public let username: String?
    public let displayUsername: String?

    public init(name: String? = nil,
                image: String? = nil,
                username: String? = nil,
                displayUsername: String? = nil)
    {
        self.name = name
        self.image = image
        self.username = username
        self.displayUsername = displayUsername
    }
}

public struct ChangePasswordRequest: Codable, Sendable, Equatable {
    public let currentPassword: String
    public let newPassword: String
    public let revokeOtherSessions: Bool?

    public init(currentPassword: String, newPassword: String, revokeOtherSessions: Bool? = nil) {
        self.currentPassword = currentPassword
        self.newPassword = newPassword
        self.revokeOtherSessions = revokeOtherSessions
    }
}

public struct UpdateUserResponse: Codable, Sendable, Equatable {
    public let status: Bool
    public let user: BetterAuthSession.User?

    public init(status: Bool, user: BetterAuthSession.User? = nil) {
        self.status = status
        self.user = user
    }
}

public struct ChangePasswordResponse: Codable, Sendable, Equatable {
    public let token: String?
    public let user: BetterAuthSession.User
    public let session: BetterAuthSession?

    public init(token: String? = nil, user: BetterAuthSession.User, session: BetterAuthSession? = nil) {
        self.token = token
        self.user = user
        self.session = session
    }
}

public struct ForgotPasswordRequest: Codable, Sendable, Equatable {
    public let email: String
    public let redirectTo: String?

    public init(email: String, redirectTo: String? = nil) {
        self.email = email
        self.redirectTo = redirectTo
    }
}

public struct ResetPasswordRequest: Codable, Sendable, Equatable {
    public let token: String
    public let newPassword: String

    public init(token: String, newPassword: String) {
        self.token = token
        self.newPassword = newPassword
    }
}

public struct SendVerificationEmailRequest: Codable, Sendable, Equatable {
    public let email: String?
    public let callbackURL: String?

    public init(email: String? = nil, callbackURL: String? = nil) {
        self.email = email
        self.callbackURL = callbackURL
    }
}

public struct VerifyEmailRequest: Codable, Sendable, Equatable {
    public let token: String

    public init(token: String) {
        self.token = token
    }
}

public enum VerifyEmailResult: Codable, Sendable, Equatable {
    case verified
    case signedIn(BetterAuthSession)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self = .signedIn(session)
            return
        }
        if let response = try? container.decode(SocialSignInTransportResponse.self),
           let session = response.materializedSession
        {
            self = .signedIn(session)
            return
        }
        let response = try container.decode(VerifyEmailResponse.self)
        if let session = response.session {
            self = .signedIn(session)
        } else {
            self = .verified
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .verified:
            try container.encode(VerifyEmailResponse(status: true, session: nil))

        case let .signedIn(session):
            try container.encode(VerifyEmailResponse(status: true, session: session))
        }
    }
}

public struct ChangeEmailRequest: Codable, Sendable, Equatable {
    public let newEmail: String
    public let callbackURL: String?

    public init(newEmail: String, callbackURL: String? = nil) {
        self.newEmail = newEmail
        self.callbackURL = callbackURL
    }
}

private struct VerifyEmailResponse: Codable, Equatable {
    let status: Bool
    let session: BetterAuthSession?
}

public struct SessionOrUserResponse: Codable, Sendable, Equatable {
    public let status: Bool
    public let session: BetterAuthSession?
    public let user: BetterAuthSession.User

    public init(status: Bool, session: BetterAuthSession? = nil, user: BetterAuthSession.User) {
        self.status = status
        self.session = session
        self.user = user
    }
}

private typealias EmailOTPVerifyResponse = SessionOrUserResponse

// MARK: - Account Lifecycle

public struct DeleteUserRequest: Codable, Sendable, Equatable {
    public let callbackURL: String?
    public let token: String?

    public init(callbackURL: String? = nil, token: String? = nil) {
        self.callbackURL = callbackURL
        self.token = token
    }
}
