import Foundation

public struct AppleNativeSignInPayload: Codable, Sendable, Equatable {
    public let token: String
    public let nonce: String?
    public let authorizationCode: String?
    public let email: String?
    public let givenName: String?
    public let familyName: String?

    public init(token: String,
                nonce: String? = nil,
                authorizationCode: String? = nil,
                email: String? = nil,
                givenName: String? = nil,
                familyName: String? = nil)
    {
        self.token = token
        self.nonce = nonce
        self.authorizationCode = authorizationCode
        self.email = email
        self.givenName = givenName
        self.familyName = familyName
    }
}

public struct SocialIDTokenPayload: Codable, Sendable, Equatable {
    public struct UserProfile: Codable, Sendable, Equatable {
        public struct Name: Codable, Sendable, Equatable {
            public let firstName: String?
            public let lastName: String?

            public init(firstName: String? = nil, lastName: String? = nil) {
                self.firstName = firstName
                self.lastName = lastName
            }
        }

        public let email: String?
        public let name: Name?

        public init(email: String? = nil, name: Name? = nil) {
            self.email = email
            self.name = name
        }
    }

    public let token: String
    public let nonce: String?
    public let accessToken: String?
    public let refreshToken: String?
    public let scopes: [String]?
    public let user: UserProfile?

    public init(token: String,
                nonce: String? = nil,
                accessToken: String? = nil,
                refreshToken: String? = nil,
                scopes: [String]? = nil,
                user: UserProfile? = nil)
    {
        self.token = token
        self.nonce = nonce
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.scopes = scopes
        self.user = user
    }
}

public struct SocialSignInRequest: Codable, Sendable, Equatable {
    public let provider: String
    public let callbackURL: String?
    public let errorCallbackURL: String?
    public let disableRedirect: Bool?
    public let requestSignUp: Bool?
    public let scopes: [String]?
    public let loginHint: String?
    public let additionalData: [String: String]?
    public let idToken: SocialIDTokenPayload?

    public init(provider: String,
                callbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                disableRedirect: Bool? = nil,
                requestSignUp: Bool? = nil,
                scopes: [String]? = nil,
                loginHint: String? = nil,
                additionalData: [String: String]? = nil,
                idToken: SocialIDTokenPayload? = nil)
    {
        self.provider = provider
        self.callbackURL = callbackURL
        self.errorCallbackURL = errorCallbackURL
        self.disableRedirect = disableRedirect
        self.requestSignUp = requestSignUp
        self.scopes = scopes
        self.loginHint = loginHint
        self.additionalData = additionalData
        self.idToken = idToken
    }
}

public enum SocialSignInResult: Sendable, Equatable {
    case authorizationURL(SocialAuthorizationResponse)
    case signedIn(SocialSignInSuccessResponse)
}

public struct SocialAuthorizationResponse: Codable, Sendable, Equatable {
    public let url: String
    public let redirect: Bool

    public init(url: String, redirect: Bool) {
        self.url = url
        self.redirect = redirect
    }
}

public struct SocialSignInSuccessResponse: Codable, Sendable, Equatable {
    public let redirect: Bool
    public let token: String
    public let url: String?
    public let user: BetterAuthSession.User

    public init(redirect: Bool, token: String, url: String? = nil, user: BetterAuthSession.User) {
        self.redirect = redirect
        self.token = token
        self.url = url
        self.user = user
    }
}

public struct SocialSignInTransportResponse: Codable, Sendable, Equatable {
    public let redirect: Bool
    public let token: String?
    public let url: String?
    public let user: BetterAuthSession.User?
    public let session: BetterAuthSession?

    public init(redirect: Bool,
                token: String? = nil,
                url: String? = nil,
                user: BetterAuthSession.User? = nil,
                session: BetterAuthSession? = nil)
    {
        self.redirect = redirect
        self.token = token
        self.url = url
        self.user = user
        self.session = session
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.redirect) || container.contains(.token) || container.contains(.url) ||
            container.contains(.user) || container.contains(.session)
        {
            let value = try DecodedValue(from: decoder)
            self.init(redirect: value.redirect,
                      token: value.token,
                      url: value.url,
                      user: value.user,
                      session: value.session)
            return
        }

        let session = try BetterAuthSession(from: decoder)
        self.init(redirect: false, token: session.session.accessToken, user: session.user, session: session)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(DecodedValue(redirect: redirect,
                                          token: token,
                                          url: url,
                                          user: user,
                                          session: session))
    }

    public var signedIn: SocialSignInSuccessResponse? {
        guard redirect == false, let token, let user else { return nil }
        return SocialSignInSuccessResponse(redirect: redirect, token: token, url: url, user: user)
    }

    public var materializedSession: BetterAuthSession? {
        session
    }

    public var authorizationURL: Result<SocialAuthorizationResponse, Error> {
        guard let url else {
            return .failure(DecodingError.dataCorrupted(.init(codingPath: [],
                                                              debugDescription: "Missing social sign-in response URL")))
        }
        return .success(SocialAuthorizationResponse(url: url, redirect: redirect))
    }

    private enum CodingKeys: String, CodingKey {
        case redirect
        case token
        case url
        case user
        case session
    }

    private struct DecodedValue: Codable, Equatable {
        let redirect: Bool
        let token: String?
        let url: String?
        let user: BetterAuthSession.User?
        let session: BetterAuthSession?
    }
}

public struct SignedInTokenResponse: Codable, Sendable, Equatable {
    public let token: String
    public let user: BetterAuthSession.User

    public init(token: String, user: BetterAuthSession.User) {
        self.token = token
        self.user = user
    }
}

public typealias AnonymousSignInResponse = SignedInTokenResponse

public struct GenericOAuthSignInRequest: Codable, Sendable, Equatable {
    public let providerId: String
    public let callbackURL: String?
    public let errorCallbackURL: String?
    public let newUserCallbackURL: String?
    public let disableRedirect: Bool?
    public let requestSignUp: Bool?
    public let scopes: [String]?
    public let additionalData: [String: String]?

    public init(providerId: String,
                callbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                newUserCallbackURL: String? = nil,
                disableRedirect: Bool? = nil,
                requestSignUp: Bool? = nil,
                scopes: [String]? = nil,
                additionalData: [String: String]? = nil)
    {
        self.providerId = providerId
        self.callbackURL = callbackURL
        self.errorCallbackURL = errorCallbackURL
        self.newUserCallbackURL = newUserCallbackURL
        self.disableRedirect = disableRedirect
        self.requestSignUp = requestSignUp
        self.scopes = scopes
        self.additionalData = additionalData
    }
}

public struct GenericOAuthAuthorizationResponse: Codable, Sendable, Equatable {
    public let url: String
    public let redirect: Bool

    public init(url: String, redirect: Bool) {
        self.url = url
        self.redirect = redirect
    }
}

public struct GenericOAuthCallbackRequest: Codable, Sendable, Equatable {
    public let providerId: String
    public let code: String
    public let state: String
    public let issuer: String?

    public init(providerId: String, code: String, state: String, issuer: String? = nil) {
        self.providerId = providerId
        self.code = code
        self.state = state
        self.issuer = issuer
    }
}

public struct LinkedAccount: Codable, Sendable, Equatable {
    public let id: String
    public let providerId: String
    public let createdAt: Date?
    public let updatedAt: Date?
    public let accountId: String
    public let userId: String
    public let scopes: [String]

    public init(id: String,
                providerId: String,
                createdAt: Date? = nil,
                updatedAt: Date? = nil,
                accountId: String,
                userId: String,
                scopes: [String] = [])
    {
        self.id = id
        self.providerId = providerId
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.accountId = accountId
        self.userId = userId
        self.scopes = scopes
    }
}

public struct LinkSocialAccountRequest: Codable, Sendable, Equatable {
    public let provider: String
    public let callbackURL: String?
    public let errorCallbackURL: String?
    public let disableRedirect: Bool?
    public let requestSignUp: Bool?
    public let scopes: [String]?
    public let additionalData: [String: String]?
    public let idToken: SocialIDTokenPayload?

    public init(provider: String,
                callbackURL: String? = nil,
                errorCallbackURL: String? = nil,
                disableRedirect: Bool? = nil,
                requestSignUp: Bool? = nil,
                scopes: [String]? = nil,
                additionalData: [String: String]? = nil,
                idToken: SocialIDTokenPayload? = nil)
    {
        self.provider = provider
        self.callbackURL = callbackURL
        self.errorCallbackURL = errorCallbackURL
        self.disableRedirect = disableRedirect
        self.requestSignUp = requestSignUp
        self.scopes = scopes
        self.additionalData = additionalData
        self.idToken = idToken
    }
}

public struct LinkSocialAccountResponse: Codable, Sendable, Equatable {
    public let url: String?
    public let redirect: Bool
    public let status: Bool?

    public init(url: String? = nil, redirect: Bool, status: Bool? = nil) {
        self.url = url
        self.redirect = redirect
        self.status = status
    }
}
