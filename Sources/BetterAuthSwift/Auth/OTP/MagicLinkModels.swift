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
