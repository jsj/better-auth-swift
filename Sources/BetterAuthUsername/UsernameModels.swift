import BetterAuth

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
        self.username = username; self.password = password
    }
}
