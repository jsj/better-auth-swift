import Foundation

// MARK: - Account Lifecycle

public struct DeleteUserRequest: Codable, Sendable, Equatable {
    public let callbackURL: String?
    public let token: String?

    public init(callbackURL: String? = nil, token: String? = nil) {
        self.callbackURL = callbackURL
        self.token = token
    }
}
