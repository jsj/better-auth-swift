import BetterAuth

public struct EmailSignUpRequest: Codable, Sendable, Equatable {
    public let email: String
    public let password: String
    public let name: String
    public let username: String?
    public let displayUsername: String?
    public init(email: String, password: String, name: String, username: String? = nil,
                displayUsername: String? = nil)
    {
        self.email = email
        self.password = password
        self.name = name
        self.username = username
        self.displayUsername = displayUsername
    }
}

public struct EmailSignInRequest: Codable, Sendable, Equatable {
    public let email: String
    public let password: String
    public init(email: String, password: String) {
        self.email = email; self.password = password
    }
}

public struct ForgotPasswordRequest: Codable, Sendable, Equatable {
    public let email: String
    public let redirectTo: String?
    public init(email: String, redirectTo: String? = nil) {
        self.email = email; self.redirectTo = redirectTo
    }
}

public struct ResetPasswordRequest: Codable, Sendable, Equatable {
    public let token: String
    public let newPassword: String
    public init(token: String, newPassword: String) {
        self.token = token; self.newPassword = newPassword
    }
}

public enum EmailSignUpResult: Codable, Sendable, Equatable {
    case signedIn(BetterAuthSession)
    case verificationHeld(VerificationHeldEmailSignUp)
    case signedUp(SuccessfulEmailSignUp)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self = .signedIn(session); return
        }
        let held = try container.decode(VerificationHeldEmailSignUp.self)
        self = held.requiresVerification ? .verificationHeld(held) :
            .signedUp(.init(requiresVerification: false, user: held.user))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case let .signedIn(session): try container.encode(session)
        case let .verificationHeld(value): try container.encode(value)
        case let .signedUp(value): try container.encode(value)
        }
    }
}

public struct SuccessfulEmailSignUp: Codable, Sendable, Equatable {
    public let requiresVerification: Bool
    public let user: BetterAuthSession.User?
    public init(requiresVerification: Bool = false, user: BetterAuthSession.User? = nil) {
        self.requiresVerification = requiresVerification; self.user = user
    }
}

public struct VerificationHeldEmailSignUp: Codable, Sendable, Equatable {
    public let requiresVerification: Bool
    public let user: BetterAuthSession.User?
    public init(requiresVerification: Bool = true, user: BetterAuthSession.User? = nil) {
        self.requiresVerification = requiresVerification; self.user = user
    }
}
