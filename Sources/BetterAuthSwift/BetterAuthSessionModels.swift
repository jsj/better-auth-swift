import Foundation

public struct BetterAuthSession: Codable, Sendable, Equatable {
    public let session: Session
    public let user: User

    public init(session: Session, user: User) {
        self.session = session
        self.user = user
    }

    public func needsRefresh(clockSkew: TimeInterval) -> Bool {
        guard let expiresAt = session.expiresAt else { return false }
        return expiresAt.timeIntervalSinceNow <= clockSkew
    }

    public struct Session: Codable, Sendable, Equatable {
        public let id: String
        public let userId: String
        public let accessToken: String
        public let refreshToken: String?
        public let expiresAt: Date?

        enum CodingKeys: String, CodingKey {
            case id
            case userId
            case accessToken
            case token
            case refreshToken
            case expiresAt
        }

        public init(id: String,
                    userId: String,
                    accessToken: String,
                    refreshToken: String? = nil,
                    expiresAt: Date? = nil)
        {
            self.id = id
            self.userId = userId
            self.accessToken = accessToken
            self.refreshToken = refreshToken
            self.expiresAt = expiresAt
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            id = try container.decode(String.self, forKey: .id)
            userId = try container.decode(String.self, forKey: .userId)
            accessToken = try container.decodeIfPresent(String.self, forKey: .accessToken)
                ?? container.decode(String.self, forKey: .token)
            refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
            expiresAt = try container.decodeIfPresent(Date.self, forKey: .expiresAt)
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(id, forKey: .id)
            try container.encode(userId, forKey: .userId)
            try container.encode(accessToken, forKey: .accessToken)
            try container.encodeIfPresent(refreshToken, forKey: .refreshToken)
            try container.encodeIfPresent(expiresAt, forKey: .expiresAt)
        }
    }

    public struct User: Codable, Sendable, Equatable {
        public let id: String
        public let email: String?
        public let name: String?
        public let username: String?
        public let displayUsername: String?

        public init(id: String,
                    email: String? = nil,
                    name: String? = nil,
                    username: String? = nil,
                    displayUsername: String? = nil)
        {
            self.id = id
            self.email = email
            self.name = name
            self.username = username
            self.displayUsername = displayUsername
        }

        public func merged(with other: User) -> User {
            User(id: other.id,
                 email: other.email ?? email,
                 name: other.name ?? name,
                 username: other.username ?? username,
                 displayUsername: other.displayUsername ?? displayUsername)
        }
    }
}

public struct BetterAuthSessionListEntry: Codable, Sendable, Equatable {
    public let id: String
    public let userId: String
    public let token: String?
    public let expiresAt: Date?
    public let createdAt: Date?
    public let updatedAt: Date?
    public let ipAddress: String?
    public let userAgent: String?

    public init(id: String,
                userId: String,
                token: String? = nil,
                expiresAt: Date? = nil,
                createdAt: Date? = nil,
                updatedAt: Date? = nil,
                ipAddress: String? = nil,
                userAgent: String? = nil)
    {
        self.id = id
        self.userId = userId
        self.token = token
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.ipAddress = ipAddress
        self.userAgent = userAgent
    }
}

public struct BetterAuthDeviceSession: Codable, Sendable, Equatable {
    public let session: BetterAuthSessionListEntry
    public let user: BetterAuthSession.User

    public init(session: BetterAuthSessionListEntry, user: BetterAuthSession.User) {
        self.session = session
        self.user = user
    }
}

public struct BetterAuthSetActiveDeviceSessionRequest: Codable, Sendable, Equatable {
    public let sessionToken: String

    public init(sessionToken: String) {
        self.sessionToken = sessionToken
    }
}

public struct BetterAuthRevokeDeviceSessionRequest: Codable, Sendable, Equatable {
    public let sessionToken: String

    public init(sessionToken: String) {
        self.sessionToken = sessionToken
    }
}

public struct BetterAuthJWT: Codable, Sendable, Equatable {
    public let token: String

    public init(token: String) {
        self.token = token
    }
}

public struct BetterAuthJWKS: Codable, Sendable, Equatable {
    public let keys: [JWK]

    public init(keys: [JWK]) {
        self.keys = keys
    }
}

public struct JWK: Codable, Sendable, Equatable {
    public let keyID: String?
    public let keyType: String?
    public let algorithm: String?
    public let use: String?
    public let modulus: String?
    public let exponent: String?
    public let curve: String?
    public let x: String?
    public let y: String?

    public init(keyID: String? = nil,
                keyType: String? = nil,
                algorithm: String? = nil,
                use: String? = nil,
                modulus: String? = nil,
                exponent: String? = nil,
                curve: String? = nil,
                x: String? = nil,
                y: String? = nil)
    {
        self.keyID = keyID
        self.keyType = keyType
        self.algorithm = algorithm
        self.use = use
        self.modulus = modulus
        self.exponent = exponent
        self.curve = curve
        self.x = x
        self.y = y
    }

    enum CodingKeys: String, CodingKey {
        case keyID = "kid"
        case keyType = "kty"
        case algorithm = "alg"
        case use
        case modulus = "n"
        case exponent = "e"
        case curve = "crv"
        case x
        case y
    }
}

public struct BetterAuthStatusResponse: Codable, Sendable, Equatable {
    public let status: Bool

    public init(status: Bool) {
        self.status = status
    }
}
