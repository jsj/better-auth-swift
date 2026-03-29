import BetterAuth
import Foundation

struct AuthAPIClient {
    let client: BetterAuthClient

    func signInWithApple(payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        try await client.auth.signInWithApple(payload)
    }
}
