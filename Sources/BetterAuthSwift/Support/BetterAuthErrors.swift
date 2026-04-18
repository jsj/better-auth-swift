import Foundation

public enum BetterAuthError: LocalizedError, Sendable {
    case invalidURL
    case invalidResponse
    case requestFailed(statusCode: Int, message: String?, errorCode: AuthErrorCode?, response: ServerErrorResponse?)
    case missingSession

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid Better Auth URL."

        case .invalidResponse:
            return "Invalid Better Auth response."

        case let .requestFailed(statusCode, message, errorCode, _):
            if let errorCode {
                return errorCode.description
            }
            return message ?? "Better Auth request failed with status \(statusCode)."

        case .missingSession:
            return "No current Better Auth session."
        }
    }

    public var statusCode: Int? {
        if case let .requestFailed(statusCode, _, _, _) = self {
            return statusCode
        }
        return nil
    }

    public var authErrorCode: AuthErrorCode? {
        if case let .requestFailed(_, _, errorCode, _) = self {
            return errorCode
        }
        return nil
    }

    public var serverError: ServerErrorResponse? {
        if case let .requestFailed(_, _, _, response) = self {
            return response
        }
        return nil
    }

    public var isUnauthorized: Bool {
        statusCode == 401
    }

    public var isRateLimited: Bool {
        statusCode == 429
    }

    public var isSessionExpired: Bool {
        switch authErrorCode {
        case .sessionExpired, .sessionNotFound, .refreshTokenExpired:
            true

        default:
            isUnauthorized
        }
    }
}

public struct ServerErrorResponse: Codable, Sendable, Equatable {
    public let message: String?
    public let code: String?
    public let status: Int?
    public let statusCode: Int?

    public init(message: String? = nil, code: String? = nil, status: Int? = nil, statusCode: Int? = nil) {
        self.message = message
        self.code = code
        self.status = status
        self.statusCode = statusCode
    }
}

public enum AuthErrorCode: String, Codable, Sendable, Equatable {
    // Session
    case sessionExpired = "SESSION_EXPIRED"
    case sessionNotFound = "SESSION_NOT_FOUND"
    case refreshTokenExpired = "REFRESH_TOKEN_EXPIRED"
    case invalidRefreshToken = "INVALID_REFRESH_TOKEN"

    // Auth
    case invalidCredentials = "INVALID_CREDENTIALS"
    case invalidPassword = "INVALID_PASSWORD"
    case weakPassword = "WEAK_PASSWORD"
    case userNotFound = "USER_NOT_FOUND"
    case userAlreadyExists = "USER_ALREADY_EXISTS"
    case emailAlreadyExists = "EMAIL_ALREADY_EXISTS"
    case usernameAlreadyTaken = "USERNAME_ALREADY_TAKEN"
    case emailNotVerified = "EMAIL_NOT_VERIFIED"
    case accountNotLinked = "ACCOUNT_NOT_LINKED"

    // OTP / Verification
    case otpExpired = "OTP_EXPIRED"
    case invalidOTP = "INVALID_OTP"
    case verificationExpired = "VERIFICATION_EXPIRED"
    case invalidVerificationToken = "INVALID_VERIFICATION_TOKEN"

    // Two-Factor
    case twoFactorRequired = "TWO_FACTOR_REQUIRED"
    case twoFactorNotEnabled = "TWO_FACTOR_NOT_ENABLED"
    case invalidTOTP = "INVALID_TOTP"
    case invalidBackupCode = "INVALID_BACKUP_CODE"
    case mfaChallengeExpired = "MFA_CHALLENGE_EXPIRED"

    // OAuth
    case oauthProviderNotFound = "OAUTH_PROVIDER_NOT_FOUND"
    case oauthAccountAlreadyLinked = "OAUTH_ACCOUNT_ALREADY_LINKED"
    case oauthCodeExchangeFailed = "OAUTH_CODE_EXCHANGE_FAILED"
    case oauthStateMismatch = "OAUTH_STATE_MISMATCH"

    // Rate limiting
    case rateLimited = "RATE_LIMITED"
    case tooManyRequests = "TOO_MANY_REQUESTS"

    // Passkey
    case passkeyRegistrationFailed = "PASSKEY_REGISTRATION_FAILED"
    case passkeyAuthenticationFailed = "PASSKEY_AUTHENTICATION_FAILED"
    case passkeyNotFound = "PASSKEY_NOT_FOUND"

    // General
    case forbidden = "FORBIDDEN"
    case badRequest = "BAD_REQUEST"
    case internalServerError = "INTERNAL_SERVER_ERROR"
    case unknown = "UNKNOWN"

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        self = AuthErrorCode(rawValue: rawValue) ?? .unknown
    }

    public var description: String {
        switch self {
        case .sessionExpired: "Session has expired."
        case .sessionNotFound: "Session not found."
        case .refreshTokenExpired: "Refresh token has expired."
        case .invalidRefreshToken: "Invalid refresh token."
        case .invalidCredentials: "Invalid credentials."
        case .invalidPassword: "Invalid password."
        case .weakPassword: "Password is too weak."
        case .userNotFound: "User not found."
        case .userAlreadyExists: "User already exists."
        case .emailAlreadyExists: "Email already in use."
        case .usernameAlreadyTaken: "Username already taken."
        case .emailNotVerified: "Email not verified."
        case .accountNotLinked: "Account not linked."
        case .otpExpired: "OTP has expired."
        case .invalidOTP: "Invalid OTP code."
        case .verificationExpired: "Verification has expired."
        case .invalidVerificationToken: "Invalid verification token."
        case .twoFactorRequired: "Two-factor authentication required."
        case .twoFactorNotEnabled: "Two-factor authentication not enabled."
        case .invalidTOTP: "Invalid TOTP code."
        case .invalidBackupCode: "Invalid backup code."
        case .mfaChallengeExpired: "MFA challenge has expired."
        case .oauthProviderNotFound: "OAuth provider not found."
        case .oauthAccountAlreadyLinked: "OAuth account already linked."
        case .oauthCodeExchangeFailed: "OAuth code exchange failed."
        case .oauthStateMismatch: "OAuth state mismatch."
        case .rateLimited, .tooManyRequests: "Too many requests. Please try again later."
        case .passkeyRegistrationFailed: "Passkey registration failed."
        case .passkeyAuthenticationFailed: "Passkey authentication failed."
        case .passkeyNotFound: "Passkey not found."
        case .forbidden: "Access denied."
        case .badRequest: "Bad request."
        case .internalServerError: "Internal server error."
        case .unknown: "An unknown error occurred."
        }
    }
}

enum ErrorParsing {
    static func parse(statusCode: Int, data: Data) -> BetterAuthError {
        let message = String(data: data, encoding: .utf8)
        let serverError = try? BetterAuthCoding.makeDecoder().decode(ServerErrorResponse.self, from: data)
        let errorCode = serverError?.code.flatMap(AuthErrorCode.init(rawValue:))
        return .requestFailed(statusCode: statusCode,
                              message: serverError?.message ?? message,
                              errorCode: errorCode,
                              response: serverError)
    }

    static let sessionCleanupCodes: Set<AuthErrorCode> = [.sessionExpired, .sessionNotFound, .refreshTokenExpired,
                                                          .invalidRefreshToken]
}
