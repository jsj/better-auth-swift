import BetterAuth
import Foundation

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
        let response = try container.decode(EmailAuthResponse.self)
        guard response.token == nil else { throw BetterAuthError.invalidResponse }
        self = response.requiresVerification == true
            ? .verificationHeld(.init(user: response.user))
            : .signedUp(.init(requiresVerification: response.requiresVerification, user: response.user))
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
    /// `nil` when the server does not report why automatic sign-in was withheld.
    public let requiresVerification: Bool?
    public let user: BetterAuthSession.User?
    public init(requiresVerification: Bool? = false, user: BetterAuthSession.User? = nil) {
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

/// Upstream email auth returns a token/user envelope; custom endpoints may return a full session.
struct EmailAuthResponse: Decodable {
    let session: BetterAuthSession?
    let token: String?
    let user: BetterAuthSession.User?
    let requiresVerification: Bool?

    private enum CodingKeys: String, CodingKey {
        case token, user, requiresVerification, twoFactorRedirect
    }

    init(from decoder: Decoder) throws {
        if let session = try? BetterAuthSession(from: decoder) {
            self.session = session
            token = session.session.accessToken
            user = session.user
            requiresVerification = nil
            return
        }
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if try container.decodeIfPresent(Bool.self, forKey: .twoFactorRedirect) == true {
            throw BetterAuthError.requestFailed(statusCode: 403, message: nil,
                                                errorCode: .twoFactorRequired, response: nil)
        }
        session = nil
        token = try container.decodeIfPresent(String.self, forKey: .token)
        user = try container.decodeIfPresent(BetterAuthSession.User.self, forKey: .user)
        requiresVerification = try container.decodeIfPresent(Bool.self, forKey: .requiresVerification)
        guard user != nil || requiresVerification != nil,
              token == nil || (token?.isEmpty == false && user != nil)
        else {
            throw BetterAuthError.invalidResponse
        }
    }

    var sessionOutcome: BetterAuthPluginSessionOutcome? {
        if let session {
            return .signedIn(session)
        }
        if let token, let user {
            return .token(token, fallbackUser: user)
        }
        return nil
    }
}
