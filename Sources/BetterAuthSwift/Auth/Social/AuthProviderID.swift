import Foundation

/// A typed authentication provider identifier that still allows custom providers.
public struct AuthProviderID: RawRepresentable, Codable, Hashable, Sendable, ExpressibleByStringLiteral,
    CustomStringConvertible
{
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(stringLiteral value: String) {
        self.init(rawValue: value)
    }

    public var description: String {
        rawValue
    }
}

public extension AuthProviderID {
    static let apple = AuthProviderID(rawValue: "apple")
    static let discord = AuthProviderID(rawValue: "discord")
    static let facebook = AuthProviderID(rawValue: "facebook")
    static let github = AuthProviderID(rawValue: "github")
    static let gitlab = AuthProviderID(rawValue: "gitlab")
    static let google = AuthProviderID(rawValue: "google")
    static let microsoft = AuthProviderID(rawValue: "microsoft")
    static let spotify = AuthProviderID(rawValue: "spotify")
    static let twitch = AuthProviderID(rawValue: "twitch")
    static let twitter = AuthProviderID(rawValue: "twitter")
}
