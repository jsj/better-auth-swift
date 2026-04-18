import CryptoKit
import Foundation

public enum AppleSignInSupport {
    public struct Context: Sendable, Equatable {
        public let rawNonce: String
        public let hashedNonce: String

        public init(rawNonce: String) {
            self.rawNonce = rawNonce
            self.hashedNonce = AppleSignInSupport.sha256(rawNonce)
        }
    }

    public static func randomNonce(length: Int = 32) -> String {
        let characters = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        return String((0 ..< length).compactMap { _ in characters.randomElement() })
    }

    public static func makeContext(length: Int = 32) -> Context {
        Context(rawNonce: randomNonce(length: length))
    }

    public static func sha256(_ input: String) -> String {
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

#if canImport(AuthenticationServices)
    import AuthenticationServices

    public enum AppleSignInBridgeError: LocalizedError {
        case unexpectedCredentialType
        case missingIdentityToken
        case invalidIdentityToken

        public var errorDescription: String? {
            switch self {
            case .unexpectedCredentialType:
                "Unexpected Apple credential type."

            case .missingIdentityToken:
                "Missing Apple identity token."

            case .invalidIdentityToken:
                "Invalid Apple identity token."
            }
        }
    }

    public enum AppleSignInBridge {
        public static func configure(_ request: ASAuthorizationAppleIDRequest,
                                     context: AppleSignInSupport.Context,
                                     scopes: [ASAuthorization.Scope] = [.fullName, .email])
        {
            request.requestedScopes = scopes
            request.nonce = context.hashedNonce
        }

        public static func payload(from authorization: ASAuthorization,
                                   context: AppleSignInSupport.Context? = nil) throws -> AppleNativeSignInPayload
        {
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
                throw AppleSignInBridgeError.unexpectedCredentialType
            }

            return try payload(from: credential, context: context)
        }

        public static func payload(from credential: ASAuthorizationAppleIDCredential,
                                   context: AppleSignInSupport.Context? = nil) throws -> AppleNativeSignInPayload
        {
            guard let identityTokenData = credential.identityToken else {
                throw AppleSignInBridgeError.missingIdentityToken
            }

            guard let identityToken = String(data: identityTokenData, encoding: .utf8) else {
                throw AppleSignInBridgeError.invalidIdentityToken
            }

            let authorizationCode = credential.authorizationCode.flatMap { String(data: $0, encoding: .utf8) }

            return AppleNativeSignInPayload(token: identityToken,
                                            nonce: context?.rawNonce,
                                            authorizationCode: authorizationCode,
                                            email: credential.email,
                                            givenName: credential.fullName?.givenName,
                                            familyName: credential.fullName?.familyName)
        }
    }
#endif
