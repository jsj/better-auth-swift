import BetterAuth
import BetterAuthMagicLink
import BetterAuthTestHelpers
import Foundation
import Testing

struct BetterAuthMagicLinkTests {
    @Test
    func requestEncodesPluginPayload() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/sign-in/magic-link")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == nil)
            let payload = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: Any]
            try expect(payload?["email"] as? String == "magic@example.com")
            try expect(payload?["callbackURL"] as? String == "betterauth://success")
            try expect((payload?["metadata"] as? [String: String])?["source"] == "ios")
            return try response(for: request, statusCode: 200, data: encodeJSON(["success": true]))
        }
        let client = try makeClient(transport: transport)

        let sent = try await client.requireMagicLinks().request(.init(email: "magic@example.com",
                                                                      callbackURL: "betterauth://success",
                                                                      metadata: ["source": "ios"]))

        #expect(sent)
    }

    @Test
    func registeredModuleRequestsAndVerifiesMagicLink() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "session-1",
                                                               userId: "user-1",
                                                               accessToken: "token-1"),
                                                user: .init(id: "user-1", email: "user@example.com"))
        let transport = SequencedMockTransport([.response(statusCode: 200, encodable: ["status": true]),
                                                .response(statusCode: 200, encodable: verifiedSession)])
        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store, transport: transport, modules: [BetterAuthMagicLinkModule()])
        let magicLinks = try client.requireMagicLinks()

        #expect(try await magicLinks.request(.init(email: "user@example.com")))
        let result = try await magicLinks.verify(.init(token: "magic-token"))

        #expect(result == .signedIn(verifiedSession))
        #expect(await client.auth.currentSession() == verifiedSession)
        #expect(try store.loadSession(for: "test-key") == verifiedSession)
    }

    @Test
    func typedAccessThrowsWhenModuleIsMissing() throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore())

        #expect(throws: BetterAuthMagicLinkModuleError.notRegistered) {
            try client.requireMagicLinks()
        }
        #expect(BetterAuthMagicLinkModuleError.notRegistered.localizedDescription ==
            "Register BetterAuthMagicLinkModule() when you create BetterAuthClient.")
    }

    @Test
    func incomingURLParsingUsesConfiguredScheme() throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    callbackURLSchemes: ["betterauth"]),
                             sessionStore: InMemorySessionStore(), modules: [BetterAuthMagicLinkModule()])
        let magicLinks = try client.requireMagicLinks()
        let url =
            try #require(URL(string: "betterauth://callback/api/auth/magic-link/verify?token=magic-token&callbackURL=betterauth%3A%2F%2Fsuccess"))

        let request = try #require(magicLinks.verificationRequest(from: url))

        #expect(request.token == "magic-token")
        #expect(request.callbackURL == "betterauth://success")
    }

    @Test
    func incomingHTTPSURLRequiresBackendOrigin() throws {
        let client = try makeClient(transport: MockTransport { request in emptyResponse(for: request) })
        let magicLinks = try client.requireMagicLinks()
        let trusted = try #require(URL(string: "https://example.com/api/auth/magic-link/verify?token=trusted"))
        let untrusted = try #require(URL(string: "https://evil.example/api/auth/magic-link/verify?token=untrusted"))

        #expect(magicLinks.verificationRequest(from: trusted)?.token == "trusted")
        #expect(magicLinks.verificationRequest(from: untrusted) == nil)
    }

    @Test
    func directSessionResponseIsApplied() async throws {
        let session = BetterAuthSession(session: .init(id: "session-direct", userId: "user-direct",
                                                       accessToken: "token-direct"),
                                        user: .init(id: "user-direct", email: "direct@example.com"))
        let client = try makeClient(transport: SequencedMockTransport([.response(statusCode: 200,
                                                                                 encodable: session)]))

        let result = try await client.requireMagicLinks().verify(.init(token: "magic-token"))

        #expect(result == .signedIn(session))
        #expect(await client.auth.currentSession() == session)
    }

    @Test
    func tokenEnvelopeUsesCoreSessionMaterializer() async throws {
        let session = BetterAuthSession(session: .init(id: "session-1", userId: "user-1", accessToken: "token-1"),
                                        user: .init(id: "user-1", email: "server@example.com"))
        let fallbackUser = BetterAuthSession.User(id: "user-1", email: "fallback@example.com", name: "Fallback")
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: TokenEnvelope(token: "token-1",
                                                                                   user: fallbackUser)),
                                                .response(statusCode: 200, encodable: session)])
        let client = try makeClient(transport: transport)

        let result = try await client.requireMagicLinks().verify(.init(token: "magic-token"))

        let expected = BetterAuthSession(session: session.session, user: fallbackUser)
        #expect(result == .signedIn(expected))
        #expect(await client.auth.currentSession() == expected)
    }

    @Test
    func malformedRequestStatusIsRejected() async throws {
        let transport = MockTransport { request in
            try response(for: request, statusCode: 200, data: encodeJSON(["message": "sent"]))
        }
        let client = try makeClient(transport: transport)

        await #expect(throws: BetterAuthError.self) {
            try await client.requireMagicLinks().request(.init(email: "magic@example.com"))
        }
    }

    @Test
    func verificationFailureDoesNotMutateSession() async throws {
        let failure = MagicLinkFailure(error: "EXPIRED_TOKEN", status: 302,
                                       redirectURL: "betterauth://error?error=EXPIRED_TOKEN")
        let transport = MockTransport { request in
            try response(for: request, statusCode: 400,
                         data: encodeJSON(MagicLinkVerificationResult.failure(failure)))
        }
        let client = try makeClient(transport: transport)

        do {
            _ = try await client.requireMagicLinks().verify(.init(token: "expired-token"))
            Issue.record("Expected verification to reject the non-success response")
        } catch let error as BetterAuthError {
            #expect(error.statusCode == 400)
            #expect(error.localizedDescription.contains("EXPIRED_TOKEN"))
        }
        #expect(await client.auth.currentSession() == nil)
    }

    @Test
    func requestDoesNotRetryTransientFailure() async throws {
        let transport = CountingTransport(statusCode: 503)
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    retryPolicy: .init(maxRetries: 2,
                                                                                       baseDelay: 0,
                                                                                       maxDelay: 0,
                                                                                       jitterFactor: 0)),
                             sessionStore: InMemorySessionStore(), transport: transport,
                             modules: [BetterAuthMagicLinkModule()])

        await #expect(throws: BetterAuthError.self) {
            try await client.requireMagicLinks().request(.init(email: "magic@example.com"))
        }
        #expect(await transport.requestCount == 1)
    }

    @Test
    func successfulFailureResponseRemainsInspectable() async throws {
        let failure = MagicLinkFailure(error: "EXPIRED_TOKEN", status: 302,
                                       redirectURL: "betterauth://error?error=EXPIRED_TOKEN")
        let transport = MockTransport { request in
            try response(for: request, statusCode: 200,
                         data: encodeJSON(MagicLinkVerificationResult.failure(failure)))
        }
        let client = try makeClient(transport: transport)

        let result = try await client.requireMagicLinks().verify(.init(token: "expired-token"))

        #expect(result == .failure(failure))
        #expect(await client.auth.currentSession() == nil)
    }

    @Test
    func customEndpointsStayInsidePluginConfiguration() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/custom/magic/request")
            return try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(), transport: transport,
                             modules: [BetterAuthMagicLinkModule(endpoints: .init(requestPath: "/custom/magic/request"))])

        #expect(try await client.requireMagicLinks().request(.init(email: "magic@example.com")))
    }

    @Test
    func pluginPreservesClientAuthThrottlePolicy() async throws {
        let transport = MockTransport { request in
            try response(for: request, statusCode: 200, data: encodeJSON(["status": true]))
        }
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    authThrottlePolicy: .init(minimumInterval: 60)),
                             sessionStore: InMemorySessionStore(), transport: transport,
                             modules: [BetterAuthMagicLinkModule()])
        let magicLinks = try client.requireMagicLinks()
        _ = try await magicLinks.request(.init(email: "magic@example.com"))

        do {
            _ = try await magicLinks.request(.init(email: "magic@example.com"))
            Issue.record("Expected the client-side throttle error")
        } catch let error as BetterAuthError {
            #expect(error.statusCode == 429)
            #expect(error.authErrorCode == .tooManyRequests)
        }
    }

    private func makeClient(transport: BetterAuthTransport) throws -> BetterAuthClient {
        BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                         sessionStore: InMemorySessionStore(), transport: transport,
                         modules: [BetterAuthMagicLinkModule()])
    }
}

private struct TokenEnvelope: Encodable {
    let token: String
    let user: BetterAuthSession.User
}

private actor CountingTransport: BetterAuthTransport {
    private(set) var requestCount = 0
    let statusCode: Int

    init(statusCode: Int) {
        self.statusCode = statusCode
    }

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        requestCount += 1
        return response(for: request, statusCode: statusCode, data: Data("unavailable".utf8))
    }
}
