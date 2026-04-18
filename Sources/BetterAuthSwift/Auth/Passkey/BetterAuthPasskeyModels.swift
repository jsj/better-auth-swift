import Foundation

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

    public init(clientDataJSON: String,
                attestationObject: String? = nil,
                authenticatorData: String? = nil,
                signature: String? = nil,
                userHandle: String? = nil,
                transports: [String]? = nil)
    {
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

    public init(id: String,
                rawId: String,
                type: String = "public-key",
                authenticatorAttachment: String? = nil,
                response: PasskeyCredentialResponse,
                clientExtensionResults: [String: String]? = nil)
    {
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

    public init(id: String,
                rawId: String,
                type: String = "public-key",
                authenticatorAttachment: String? = nil,
                response: PasskeyCredentialResponse,
                clientExtensionResults: [String: String]? = nil)
    {
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
