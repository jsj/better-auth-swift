import Foundation

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

// MARK: - Account Lifecycle
