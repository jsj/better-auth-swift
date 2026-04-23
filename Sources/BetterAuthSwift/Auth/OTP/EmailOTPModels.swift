import Foundation

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
