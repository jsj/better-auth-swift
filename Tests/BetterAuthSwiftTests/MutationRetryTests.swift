import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth

struct MutationRetryTests {
    @Test(arguments: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
    func defaultRetriesDependOnRequestSemantics(method: String) async throws {
        let transport = RetryProbeTransport()
        let client = makeClient(transport)
        let (_, response) = try await client.requests.send(path: "/api/action", method: method,
                                                           requiresAuthentication: false)
        let isRead = ["GET", "HEAD", "OPTIONS"].contains(method)
        #expect(response.statusCode == (isRead ? 200 : 503))
        #expect(await transport.attempts == (isRead ? 2 : 1))
    }

    @Test
    func explicitMutationRetryIsHonored() async throws {
        let transport = RetryProbeTransport()
        let client = makeClient(transport)
        let (_, response) = try await client.requests.send(path: "/api/idempotent-action", method: "POST",
                                                           requiresAuthentication: false, allowsTransientRetry: true)
        #expect(response.statusCode == 200)
        #expect(await transport.attempts == 2)
    }

    @Test
    func changedRequestMethodUsesFinalSemantics() async throws {
        let transport = RetryProbeTransport()
        var request = BetterAuthDataRequest(path: "/api/action", requiresAuthentication: false)
        request.method = "POST"
        _ = try await makeClient(transport).requests.send(request)
        #expect(await transport.attempts == 1)
    }

    @Test(arguments: ["emailOTP", "twoFactor", "verifyEmail"])
    func consumedCodeIsNotResubmittedAfterResponseLoss(operation: String) async throws {
        let transport = RetryProbeTransport(losesResponse: true)
        let client = makeClient(transport)
        await #expect(throws: URLError.self) {
            switch operation {
            case "emailOTP":
                _ = try await client.auth.signInWithEmailOTP(.init(email: "test@example.com", otp: "123456"))

            case "twoFactor":
                _ = try await client.auth.verifyTwoFactorOTP(.init(code: "123456"))

            default:
                _ = try await client.auth.verifyEmail(.init(token: "one-time-token"))
            }
        }
        #expect(await transport.attempts == 1)
    }

    private func makeClient(_ transport: any BetterAuthTransport) -> BetterAuthClient {
        BetterAuthClient(configuration: .init(baseURL: URL(string: "https://example.com")!,
                                              retryPolicy: .init(baseDelay: 0, jitterFactor: 0)),
                         sessionStore: InMemorySessionStore(), transport: transport)
    }
}

private actor RetryProbeTransport: BetterAuthTransport {
    let losesResponse: Bool
    private(set) var attempts = 0

    init(losesResponse: Bool = false) {
        self.losesResponse = losesResponse
    }

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        attempts += 1
        if losesResponse {
            throw URLError(.networkConnectionLost)
        }
        return response(for: request, statusCode: attempts == 1 ? 503 : 200, data: Data())
    }
}
