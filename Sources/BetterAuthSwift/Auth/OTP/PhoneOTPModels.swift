import Foundation

public struct PhoneOTPRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String

    public init(phoneNumber: String) {
        self.phoneNumber = phoneNumber
    }
}

public struct PhoneOTPRequestResponse: Codable, Sendable, Equatable {
    public let message: String?
    public let success: Bool?
    public let status: Bool?

    public init(message: String? = nil, success: Bool? = nil, status: Bool? = nil) {
        self.message = message
        self.success = success
        self.status = status
    }
}

public struct PhoneOTPVerifyRequest: Codable, Sendable, Equatable {
    public let phoneNumber: String
    public let code: String
    public let disableSession: Bool?
    public let updatePhoneNumber: Bool?

    public init(phoneNumber: String,
                code: String,
                disableSession: Bool? = nil,
                updatePhoneNumber: Bool? = nil)
    {
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
