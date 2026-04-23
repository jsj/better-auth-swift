import Foundation

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

public struct TwoFactorDisableRequest: Codable, Sendable, Equatable {
    public let password: String

    public init(password: String) {
        self.password = password
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

    public init(id: String,
                email: String? = nil,
                name: String? = nil,
                username: String? = nil,
                displayUsername: String? = nil,
                twoFactorEnabled: Bool)
    {
        self.id = id
        self.email = email
        self.name = name
        self.username = username
        self.displayUsername = displayUsername
        self.twoFactorEnabled = twoFactorEnabled
    }
}
