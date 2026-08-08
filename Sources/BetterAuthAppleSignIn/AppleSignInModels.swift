public struct AppleNativeSignInPayload: Codable, Sendable, Equatable {
    public let token: String
    public let nonce: String?
    public let authorizationCode: String?
    public let email: String?
    public let givenName: String?
    public let familyName: String?
    public init(token: String, nonce: String? = nil, authorizationCode: String? = nil, email: String? = nil,
                givenName: String? = nil, familyName: String? = nil)
    {
        self.token = token
        self.nonce = nonce
        self.authorizationCode = authorizationCode
        self.email = email
        self.givenName = givenName
        self.familyName = familyName
    }
}
