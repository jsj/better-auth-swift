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

        public init(
            id: String,
            userId: String,
            accessToken: String,
            refreshToken: String? = nil,
            expiresAt: Date? = nil
        ) {
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

        public init(
            id: String,
            email: String? = nil,
            name: String? = nil,
            username: String? = nil,
            displayUsername: String? = nil
        ) {
            self.id = id
            self.email = email
            self.name = name
            self.username = username
            self.displayUsername = displayUsername
        }

        public func merged(with other: User) -> User {
            User(
                id: other.id,
                email: other.email ?? email,
                name: other.name ?? name,
                username: other.username ?? username,
                displayUsername: other.displayUsername ?? displayUsername
            )
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

    public init(
        id: String,
        userId: String,
        token: String? = nil,
        expiresAt: Date? = nil,
        createdAt: Date? = nil,
        updatedAt: Date? = nil,
        ipAddress: String? = nil,
        userAgent: String? = nil
    ) {
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

    public init(
        keyID: String? = nil,
        keyType: String? = nil,
        algorithm: String? = nil,
        use: String? = nil,
        modulus: String? = nil,
        exponent: String? = nil,
        curve: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
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

public struct AppleNativeSignInPayload: Codable, Sendable, Equatable {
    public let token: String
    public let nonce: String?
    public let authorizationCode: String?
    public let email: String?
    public let givenName: String?
    public let familyName: String?

    public init(
        token: String,
        nonce: String? = nil,
        authorizationCode: String? = nil,
        email: String? = nil,
        givenName: String? = nil,
        familyName: String? = nil
    ) {
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

    public init(
        token: String,
        nonce: String? = nil,
        accessToken: String? = nil,
        refreshToken: String? = nil,
        scopes: [String]? = nil,
        user: UserProfile? = nil
    ) {
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

    public init(
        provider: String,
        callbackURL: String? = nil,
        errorCallbackURL: String? = nil,
        disableRedirect: Bool? = nil,
        requestSignUp: Bool? = nil,
        scopes: [String]? = nil,
        loginHint: String? = nil,
        additionalData: [String: String]? = nil,
        idToken: SocialIDTokenPayload? = nil
    ) {
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

    public init(
        redirect: Bool,
        token: String? = nil,
        url: String? = nil,
        user: BetterAuthSession.User? = nil,
        session: BetterAuthSession? = nil
    ) {
        self.redirect = redirect
        self.token = token
        self.url = url
        self.user = user
        self.session = session
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let session = try? container.decode(BetterAuthSession.self) {
            self.init(redirect: false, token: session.session.accessToken, user: session.user, session: session)
            return
        }

        let value = try container.decode(DecodedValue.self)
        self.init(
            redirect: value.redirect,
            token: value.token,
            url: value.url,
            user: value.user,
            session: value.session
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(DecodedValue(
            redirect: redirect,
            token: token,
            url: url,
            user: user,
            session: session
        ))
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
            return .failure(DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Missing social sign-in response URL")))
        }
        return .success(SocialAuthorizationResponse(url: url, redirect: redirect))
    }

    private struct DecodedValue: Codable, Sendable, Equatable {
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

    public init(
        providerId: String,
        callbackURL: String? = nil,
        errorCallbackURL: String? = nil,
        newUserCallbackURL: String? = nil,
        disableRedirect: Bool? = nil,
        requestSignUp: Bool? = nil,
        scopes: [String]? = nil,
        additionalData: [String: String]? = nil
    ) {
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

    public init(
        id: String,
        providerId: String,
        createdAt: Date? = nil,
        updatedAt: Date? = nil,
        accountId: String,
        userId: String,
        scopes: [String] = []
    ) {
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

    public init(
        provider: String,
        callbackURL: String? = nil,
        errorCallbackURL: String? = nil,
        disableRedirect: Bool? = nil,
        requestSignUp: Bool? = nil,
        scopes: [String]? = nil,
        additionalData: [String: String]? = nil,
        idToken: SocialIDTokenPayload? = nil
    ) {
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

public struct PasskeyRegistrationOptionsRequest: Sendable, Equatable {
    public let name: String?
    public let authenticatorAttachment: String?

    public init(name: String? = nil, authenticatorAttachment: String? = nil) {
        self.name = name
        self.authenticatorAttachment = authenticatorAttachment
    }
}

public struct PasskeyAuthenticateOptionsRequest: Sendable, Equatable {
    public init() {}
}

public struct PublicKeyCredentialDescriptor: Codable, Sendable, Equatable {
    public let id: String
    public let type: String
    public let transports: [String]?

    public init(id: String, type: String, transports: [String]? = nil) {
        self.id = id
        self.type = type
        self.transports = transports
    }
}

public struct PasskeyRegistrationOptions: Codable, Sendable, Equatable {
    public struct RelyingParty: Codable, Sendable, Equatable {
        public let name: String
        public let id: String
    }

    public struct UserIdentity: Codable, Sendable, Equatable {
        public let id: String
        public let name: String
        public let displayName: String
    }

    public struct PublicKeyCredentialParameter: Codable, Sendable, Equatable {
        public let type: String
        public let alg: Int
    }

    public struct AuthenticatorSelection: Codable, Sendable, Equatable {
        public let authenticatorAttachment: String?
        public let requireResidentKey: Bool?
        public let residentKey: String?
        public let userVerification: String?
    }

    public let challenge: String
    public let rp: RelyingParty
    public let user: UserIdentity
    public let pubKeyCredParams: [PublicKeyCredentialParameter]
    public let timeout: Int?
    public let excludeCredentials: [PublicKeyCredentialDescriptor]?
    public let authenticatorSelection: AuthenticatorSelection?
    public let attestation: String?
}

public struct PasskeyAuthenticationOptions: Codable, Sendable, Equatable {
    public let challenge: String
    public let timeout: Int?
    public let rpId: String?
    public let allowCredentials: [PublicKeyCredentialDescriptor]?
    public let userVerification: String?
}

public struct PasskeyCredentialResponse: Codable, Sendable, Equatable {
    public let clientDataJSON: String
    public let attestationObject: String?
    public let authenticatorData: String?
    public let signature: String?
    public let userHandle: String?
    public let transports: [String]?

    public init(
        clientDataJSON: String,
        attestationObject: String? = nil,
        authenticatorData: String? = nil,
        signature: String? = nil,
        userHandle: String? = nil,
        transports: [String]? = nil
    ) {
        self.clientDataJSON = clientDataJSON
        self.attestationObject = attestationObject
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
        self.transports = transports
    }
}

public struct PasskeyRegistrationCredential: Codable, Sendable, Equatable {
    public let id: String
    public let rawId: String
    public let type: String
    public let authenticatorAttachment: String?
    public let response: PasskeyCredentialResponse
    public let clientExtensionResults: [String: String]?

    public init(
        id: String,
        rawId: String,
        type: String = "public-key",
        authenticatorAttachment: String? = nil,
        response: PasskeyCredentialResponse,
        clientExtensionResults: [String: String]? = nil
    ) {
        self.id = id
        self.rawId = rawId
        self.type = type
        self.authenticatorAttachment = authenticatorAttachment
        self.response = response
        self.clientExtensionResults = clientExtensionResults
    }
}

public struct PasskeyAuthenticationCredential: Codable, Sendable, Equatable {
    public let id: String
    public let rawId: String
    public let type: String
    public let authenticatorAttachment: String?
    public let response: PasskeyCredentialResponse
    public let clientExtensionResults: [String: String]?

    public init(
        id: String,
        rawId: String,
        type: String = "public-key",
        authenticatorAttachment: String? = nil,
        response: PasskeyCredentialResponse,
        clientExtensionResults: [String: String]? = nil
    ) {
        self.id = id
        self.rawId = rawId
        self.type = type
        self.authenticatorAttachment = authenticatorAttachment
        self.response = response
        self.clientExtensionResults = clientExtensionResults
    }
}

public struct PasskeyRegistrationRequest: Codable, Sendable, Equatable {
    public let response: PasskeyRegistrationCredential
    public let name: String?

    public init(response: PasskeyRegistrationCredential, name: String? = nil) {
        self.response = response
        self.name = name
    }
}

public struct PasskeyAuthenticationRequest: Codable, Sendable, Equatable {
    public let response: PasskeyAuthenticationCredential

    public init(response: PasskeyAuthenticationCredential) {
        self.response = response
    }
}

public struct Passkey: Codable, Sendable, Equatable {
    public let id: String
    public let name: String?
    public let publicKey: String
    public let userId: String
    public let credentialID: String
    public let counter: Int
    public let deviceType: String
    public let backedUp: Bool
    public let transports: String?
    public let createdAt: Date?
    public let aaguid: String?
}

public struct UpdatePasskeyRequest: Codable, Sendable, Equatable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

public struct UpdatePasskeyResponse: Codable, Sendable, Equatable {
    public let passkey: Passkey
}

public struct DeletePasskeyRequest: Codable, Sendable, Equatable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public struct MagicLinkRequest: Codable, Sendable, Equatable {
    public let email: String
    public let name: String?
    public let callbackURL: String?
    public let newUserCallbackURL: String?
    public let errorCallbackURL: String?
    public let metadata: [String: String]?

    public init(
        email: String,
        name: String? = nil,
        callbackURL: String? = nil,
        newUserCallbackURL: String? = nil,
        errorCallbackURL: String? = nil,
        metadata: [String: String]? = nil
    ) {
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

    public init(
        token: String,
        callbackURL: String? = nil,
        newUserCallbackURL: String? = nil,
        errorCallbackURL: String? = nil
    ) {
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
    public let message: String

    public init(message: String) {
        self.message = message
    }
}

public struct PhoneOTPVerifyRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String
    public let code: String
    public let disableSession: Bool?
    public let updatePhoneNumber: Bool?

    public init(
        phoneNumber: String,
        code: String,
        disableSession: Bool? = nil,
        updatePhoneNumber: Bool? = nil
    ) {
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

    public init(
        id: String,
        email: String? = nil,
        name: String? = nil,
        username: String? = nil,
        displayUsername: String? = nil,
        twoFactorEnabled: Bool
    ) {
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
        if let response = try? container.decode(SocialSignInTransportResponse.self), let session = response.materializedSession {
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
        if let response = try? container.decode(SocialSignInTransportResponse.self), let session = response.materializedSession {
            self = .signedIn(session)
            return
        }

        self = .failure(try container.decode(MagicLinkFailure.self))
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

    public init(
        email: String,
        password: String,
        name: String,
        username: String? = nil,
        displayUsername: String? = nil
    ) {
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
        self = held.requiresVerification ? .verificationHeld(held) : .signedUp(.init(
            requiresVerification: held.requiresVerification,
            user: held.user
        ))
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

    public init(
        name: String? = nil,
        image: String? = nil,
        username: String? = nil,
        displayUsername: String? = nil
    ) {
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
        if let response = try? container.decode(SocialSignInTransportResponse.self), let session = response.materializedSession {
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

private struct VerifyEmailResponse: Codable, Sendable, Equatable {
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
