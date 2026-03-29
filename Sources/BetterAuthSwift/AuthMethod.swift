import Foundation

public enum AuthMethod: String, CaseIterable, Sendable, Codable {
    case emailPassword
    case usernamePassword
    case magicLink
    case emailOTP
    case phoneOTP
    case apple
    case anonymous
    case passkey
    case twoFactor
}
