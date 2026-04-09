import BetterAuth
import Foundation

enum AuthOption: Identifiable {
    case authMethod(AuthMethod)
    case emailVerification
    case profile
    case sessionManagement
    case linkedAccounts
    case jwt

    static let allCases: [AuthOption] = [.authMethod(.apple),
                                         .authMethod(.emailPassword),
                                         .authMethod(.usernamePassword),
                                         .authMethod(.magicLink),
                                         .authMethod(.emailOTP),
                                         .authMethod(.phoneOTP),
                                         .authMethod(.twoFactor),
                                         .emailVerification,
                                         .profile,
                                         .sessionManagement,
                                         .linkedAccounts,
                                         .authMethod(.passkey),
                                         .jwt,
                                         .authMethod(.anonymous)]

    var id: String {
        switch self {
        case let .authMethod(method):
            "method.\(method.rawValue)"

        case .emailVerification:
            "emailVerification"

        case .profile:
            "profile"

        case .sessionManagement:
            "sessionManagement"

        case .linkedAccounts:
            "linkedAccounts"

        case .jwt:
            "jwt"
        }
    }

    var title: String {
        switch self {
        case .authMethod(.apple): "Apple Sign In"
        case .authMethod(.emailPassword): "Email + Password"
        case .authMethod(.usernamePassword): "Username"
        case .authMethod(.magicLink): "Magic Link"
        case .authMethod(.emailOTP): "Email OTP"
        case .authMethod(.phoneOTP): "Phone OTP"
        case .authMethod(.twoFactor): "Two Factor"
        case .emailVerification: "Email Verification"
        case .profile: "Profile"
        case .sessionManagement: "Session Management"
        case .linkedAccounts: "Linked Accounts"
        case .authMethod(.passkey): "Passkeys"
        case .jwt: "JWT"
        case .authMethod(.anonymous): "Anonymous"
        }
    }

    var subtitle: String {
        switch self {
        case .authMethod(.apple): "Use native Apple sign-in"
        case .authMethod(.emailPassword): "Sign up, sign in, and reset passwords"
        case .authMethod(.usernamePassword): "Check availability and sign in"
        case .authMethod(.magicLink): "Request and verify email sign-in links"
        case .authMethod(.emailOTP): "Request and verify one-time passcodes"
        case .authMethod(.phoneOTP): "Request and verify phone sign-in codes"
        case .authMethod(.twoFactor): "Enable and verify 2FA challenges"
        case .emailVerification: "Send and verify email actions"
        case .profile: "Update the current user profile"
        case .sessionManagement: "Inspect and revoke sessions"
        case .linkedAccounts: "Load linked social accounts"
        case .authMethod(.passkey): "Inspect registered passkeys"
        case .jwt: "Fetch a session JWT"
        case .authMethod(.anonymous): "Create or delete anonymous users"
        }
    }

    var symbolName: String {
        switch self {
        case .authMethod(.apple): "apple.logo"
        case .authMethod(.emailPassword): "envelope.badge"
        case .authMethod(.usernamePassword): "at"
        case .authMethod(.magicLink): "link"
        case .authMethod(.emailOTP): "number.square"
        case .authMethod(.phoneOTP): "message.badge"
        case .authMethod(.twoFactor): "lock.shield"
        case .emailVerification: "checkmark.seal"
        case .profile: "person.crop.circle"
        case .sessionManagement: "rectangle.stack.badge.person.crop"
        case .linkedAccounts: "person.2.badge.key"
        case .authMethod(.passkey): "key.viewfinder"
        case .jwt: "doc.text.magnifyingglass"
        case .authMethod(.anonymous): "person.crop.circle.badge.questionmark"
        }
    }
}
