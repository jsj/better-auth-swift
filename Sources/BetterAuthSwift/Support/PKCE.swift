import CryptoKit
import Foundation
import Security

public enum PKCEFlow {
    public struct Challenge: Sendable, Equatable {
        public let codeVerifier: String
        public let codeChallenge: String
        public let codeChallengeMethod: String

        public init(codeVerifier: String, codeChallenge: String, codeChallengeMethod: String = "S256") {
            self.codeVerifier = codeVerifier
            self.codeChallenge = codeChallenge
            self.codeChallengeMethod = codeChallengeMethod
        }
    }

    public static func generateChallenge() throws -> Challenge {
        let verifier = try generateCodeVerifier()
        let challenge = generateCodeChallenge(verifier)
        return Challenge(codeVerifier: verifier, codeChallenge: challenge)
    }

    public static func generateCodeVerifier(length: Int = 64) throws -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw BetterAuthError.randomGenerationFailed
        }
        return Data(bytes).base64URLEncoded()
    }

    public static func generateCodeChallenge(_ verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncoded()
    }
}

extension Data {
    func base64URLEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
