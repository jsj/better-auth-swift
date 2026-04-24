import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth
@testable import BetterAuthSwiftUI

struct EmailOtpMagicLinkAndRequestClientTests {
    @Test
    func requestClientEncodesDatesAsISO8601() async throws {
        struct DatePayload: Encodable {
            let issuedAt: Date
        }

        let issuedAt = try #require(ISO8601DateFormatter().date(from: "2026-04-24T12:00:00Z"))
        let transport = MockTransport { request in
            let body = try #require(request.httpBody)
            let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: String])
            try expect(json["issuedAt"] == "2026-04-24T12:00:00Z")
            return emptyResponse(for: request)
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.requests.sendWithoutDecoding(path: "/date",
                                                      body: DatePayload(issuedAt: issuedAt),
                                                      requiresAuthentication: false)
    }

    @Test
    func emailOTPRequestUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/email-otp/send-verification-otp")
            try expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(EmailOTPRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.email == "otp@example.com")
            try expect(payload.type == .signIn)

            return try response(for: request, statusCode: 200, data: encodeJSON(EmailOTPRequestResponse(success: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let success = try await client.auth.requestEmailOTP(.init(email: "otp@example.com", type: .signIn))
        #expect(success)
    }

    @Test
    func emailOTPSignInPersistsNativeSessionAndSupportsRestore() async throws {
        let signedInSession = BetterAuthSession(session: .init(id: "otp-session",
                                                               userId: "user-otp",
                                                               accessToken: "otp-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp", email: "otp@example.com", name: "OTP User"))

        let protectedPayload = ProtectedResponse(email: "otp@example.com")
        let transport = SequencedMockTransport([.response(statusCode: 200,
                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                   token: signedInSession
                                                                                                       .session
                                                                                                       .accessToken,
                                                                                                   user: signedInSession
                                                                                                       .user,
                                                                                                   session: signedInSession)),
                                                .response(statusCode: 200, encodable: protectedPayload)])

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: transport)

        let session = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "123456",
                                                                     name: "OTP User"))
        #expect(session.session.id == signedInSession.session.id)
        #expect(session.session.accessToken == signedInSession.session.accessToken)
        #expect(session.user.email == signedInSession.user.email)

        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == signedInSession.session.accessToken)

        let restored = try await client.auth.restoreOrRefreshSession()
        #expect(restored?.session.accessToken == signedInSession.session.accessToken)

        let protected: ProtectedResponse = try await client.requests.sendJSON(path: "/api/me")
        #expect(protected == protectedPayload)
    }

    @Test
    func emailOTPSignInPreservesStableFailureContracts() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: SequencedMockTransport([.response(statusCode: 400,
                                                                          jsonObject: ["code": "INVALID_OTP",
                                                                                       "message": "Invalid OTP"]),
                                                                .response(statusCode: 400,
                                                                          jsonObject: ["code": "OTP_EXPIRED",
                                                                                       "message": "OTP expired"]),
                                                                .response(statusCode: 403,
                                                                          jsonObject: ["code": "TOO_MANY_ATTEMPTS",
                                                                                       "message": "Too many attempts"])]))

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "INVALID_OTP",
                                                                      "message": "Invalid OTP"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "111111"))
        }

        await assertRequestFailedJSON(statusCode: 400, expectedJSON: ["code": "OTP_EXPIRED",
                                                                      "message": "OTP expired"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "222222"))
        }

        await assertRequestFailedJSON(statusCode: 403, expectedJSON: ["code": "TOO_MANY_ATTEMPTS",
                                                                      "message": "Too many attempts"])
        {
            _ = try await client.auth.signInWithEmailOTP(.init(email: "otp@example.com", otp: "333333"))
        }
    }

    @Test
    func emailOTPVerifyUpdatesCurrentUserWithoutPersistingNewSession() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-otp",
                                                               accessToken: "existing-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp",
                                                            email: "otp@example.com",
                                                            name: "OTP User",
                                                            username: "otp_user",
                                                            displayUsername: "OTP User"))
        let verifiedUser = BetterAuthSession.User(id: "user-otp",
                                                  email: "otp@example.com",
                                                  name: "Verified OTP User")

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: EmailOTPVerifyResult
                                                                              .verified(verifiedUser))]))

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.verifyEmailOTP(.init(email: "otp@example.com", otp: "123456"))

        guard case let .verified(user) = result else {
            Issue.record("Expected verified email OTP result")
            return
        }

        #expect(user == verifiedUser)
        let current = await client.auth.currentSession()
        #expect(current?.session.accessToken == existingSession.session.accessToken)
        #expect(current?.user.name == "Verified OTP User")
        #expect(current?.user.username == "otp_user")
        #expect(current?.user.displayUsername == "OTP User")
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == existingSession.session.accessToken)
        #expect(stored?.user.name == "Verified OTP User")
        #expect(stored?.user.username == "otp_user")
        #expect(stored?.user.displayUsername == "OTP User")
    }

    @Test
    func emailOTPVerifyForDifferentUserDoesNotOverwriteCurrentSession() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "existing-session",
                                                               userId: "user-current",
                                                               accessToken: "existing-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-current",
                                                            email: "current@example.com",
                                                            name: "Current User",
                                                            username: "current_user",
                                                            displayUsername: "Current User"))
        let verifiedUser = BetterAuthSession.User(id: "user-other",
                                                  email: "other@example.com",
                                                  name: "Other User")

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: EmailOTPVerifyResult
                                                                              .verified(verifiedUser))]))

        try await client.auth.updateSession(existingSession)
        let result = try await client.auth.verifyEmailOTP(.init(email: "other@example.com", otp: "123456"))

        guard case let .verified(user) = result else {
            Issue.record("Expected verified email OTP result")
            return
        }

        #expect(user == verifiedUser)
        let current = await client.auth.currentSession()
        #expect(current == existingSession)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored == existingSession)
    }

    func emailOTPVerifyWithAutoSignInPersistsNativeSession() async throws {
        let verifiedSession = BetterAuthSession(session: .init(id: "otp-verified-session",
                                                               userId: "user-otp",
                                                               accessToken: "verified-otp-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-otp", email: "otp@example.com",
                                                            name: "Verified OTP User"))

        let store = InMemorySessionStore()
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: URL(string: "https://example.com")!,
                                                                    storage: .init(key: "test-key")),
                             sessionStore: store,
                             transport: SequencedMockTransport([.response(statusCode: 200,
                                                                          encodable: SocialSignInTransportResponse(redirect: false,
                                                                                                                   token: verifiedSession
                                                                                                                       .session
                                                                                                                       .accessToken,
                                                                                                                   user: verifiedSession
                                                                                                                       .user,
                                                                                                                   session: verifiedSession))]))

        let result = try await client.auth.verifyEmailOTP(.init(email: "otp@example.com", otp: "654321"))

        guard case let .signedIn(session) = result else {
            Issue.record("Expected signed-in email OTP verify result")
            return
        }

        #expect(session.session.accessToken == verifiedSession.session.accessToken)
        let current = await client.auth.currentSession()
        #expect(current?.session.accessToken == verifiedSession.session.accessToken)
        let stored = try store.loadSession(for: "test-key")
        #expect(stored?.session.accessToken == verifiedSession.session.accessToken)
    }

    @Test
    func phoneOTPRequestUsesConfiguredEndpoint() async throws {
        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/phone-number/send-otp")
            try expect(request.httpMethod == "POST")
            let payload = try JSONDecoder().decode(PhoneOTPRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.phoneNumber == "+15555550123")

            return try response(for: request, statusCode: 200,
                                data: encodeJSON(PhoneOTPRequestResponse(message: "otp queued", success: true)))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        let success = try await client.auth.requestPhoneOTP(PhoneOTPRequest(phoneNumber: "+15555550123"))
        #expect(success)
    }

    @Test
    func phoneNumberVerifyUsesAuthenticatedRouteAndUpdatesReturnedUserWhenUpdatingPhoneNumber() async throws {
        let existingSession = BetterAuthSession(session: .init(id: "phone-session",
                                                               userId: "user-phone",
                                                               accessToken: "phone-token",
                                                               expiresAt: Date().addingTimeInterval(3600)),
                                                user: .init(id: "user-phone", email: "phone@example.com",
                                                            name: "Phone User"))

        let transport = MockTransport { request in
            try expect(request.url?.path == "/api/auth/phone-number/verify")
            try expect(request.httpMethod == "POST")
            try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer phone-token")
            let payload = try JSONDecoder().decode(PhoneOTPVerifyRequest.self, from: try requireValue(request.httpBody))
            try expect(payload.phoneNumber == "+15555550123")
            try expect(payload.code == "123456")
            try expect(payload.disableSession == true)
            try expect(payload.updatePhoneNumber == true)

            return try response(for: request,
                                statusCode: 200,
                                data: encodeJSON(PhoneOTPVerifyResponse(status: true,
                                                                        user: BetterAuthSession.User(id: "user-phone",
                                                                                                     email: "phone@example.com",
                                                                                                     name: "Phone User"))))
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)

        try await client.auth.updateSession(existingSession)
        let verified = try await client.auth.verifyPhoneNumber(PhoneOTPVerifyRequest(phoneNumber: "+15555550123",
                                                                                     code: "123456",
                                                                                     disableSession: true,
                                                                                     updatePhoneNumber: true))
        #expect(verified == PhoneOTPVerifyResponse(status: true,
                                                   user: BetterAuthSession.User(id: "user-phone",
                                                                                email: "phone@example.com",
                                                                                name: "Phone User")))
        #expect(await client.auth.currentSession()?.session.accessToken == "phone-token")
    }

    @Test
    func requestPhoneOTPThrowsWhenResponseOmitsSuccessAndStatus() async throws {
        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: MockTransport { request in
                                 try response(for: request,
                                              statusCode: 200,
                                              data: encodeJSON(PhoneOTPRequestResponse(message: "ambiguous")))
                             })

        do {
            _ = try await client.auth.requestPhoneOTP(PhoneOTPRequest(phoneNumber: "+15555550123"))
            Issue.record("Expected BetterAuthError.invalidResponse")
        } catch let error as BetterAuthError {
            #expect(error.localizedDescription == BetterAuthError.invalidResponse.localizedDescription)
        }
    }

    @Test
    func requestClientAppliesConfiguredTimeoutToAuthenticatedRequests() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            return emptyResponse(for: request)
        }
        let configuration = BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                    networking: .init(timeoutInterval: 7))
        let client = BetterAuthClient(configuration: configuration,
                                      sessionStore: InMemorySessionStore(),
                                      transport: transport)
        try await client.auth
            .updateSession(BetterAuthSession(session: .init(id: "session-1", userId: "user-1",
                                                            accessToken: "current-token",
                                                            expiresAt: Date().addingTimeInterval(3600)),
                                             user: .init(id: "user-1", email: "test@example.com")))

        _ = try await client.requests.send(path: "/protected", retryOnUnauthorized: false)
        let captured = try #require(requests.withLock { $0.first })
        #expect(captured.timeoutInterval == 7)
        #expect(captured.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
    }

    @Test
    func requestClientAppliesConfiguredTimeoutToUnauthenticatedRequests() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            return emptyResponse(for: request)
        }
        let configuration = BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                    networking: .init(timeoutInterval: 7))
        let client = BetterAuthClient(configuration: configuration,
                                      sessionStore: InMemorySessionStore(),
                                      transport: transport)

        _ = try await client.requests.send(path: "/public",
                                           method: "POST",
                                           requiresAuthentication: false,
                                           retryOnUnauthorized: false)
        let captured = try #require(requests.withLock { $0.first })
        #expect(captured.timeoutInterval == 7)
        #expect(captured.value(forHTTPHeaderField: "Authorization") == nil)
    }

    @Test
    func requestClientThrowsWhenRetriedRawSendStillFails() async throws {
        let requests = Locked<[URLRequest]>([])
        let transport = MockTransport { request in
            requests.withLock { $0.append(request) }
            switch request.url?.path {
            case "/protected":
                if request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token" {
                    return try response(for: request,
                                        statusCode: 401,
                                        data: encodeJSON(ServerErrorResponse(message: "expired",
                                                                             code: "SESSION_EXPIRED")))
                }
                return try response(for: request,
                                    statusCode: 403,
                                    data: encodeJSON(ServerErrorResponse(message: "forbidden", code: "FORBIDDEN")))

            case "/api/auth/get-session":
                try expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer current-token")
                let refreshed = BetterAuthSession(session: .init(id: "session-2",
                                                                 userId: "user-1",
                                                                 accessToken: "refreshed-token",
                                                                 expiresAt: Date().addingTimeInterval(3600)),
                                                  user: .init(id: "user-1", email: "test@example.com"))
                return try response(for: request, statusCode: 200, data: encodeJSON(refreshed))

            default:
                Issue.record("Unexpected path: \(request.url?.path ?? "nil")")
                return emptyResponse(for: request)
            }
        }

        let client =
            BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com"))),
                             sessionStore: InMemorySessionStore(),
                             transport: transport)
        try await client.auth.updateSession(BetterAuthSession(session: .init(id: "session-1",
                                                                             userId: "user-1",
                                                                             accessToken: "current-token",
                                                                             refreshToken: "refresh-token",
                                                                             expiresAt: Date()
                                                                                 .addingTimeInterval(3600)),
                                                              user: .init(id: "user-1", email: "test@example.com")))

        do {
            _ = try await client.requests.send(path: "/protected")
            Issue.record("Expected retried raw send to throw")
        } catch let BetterAuthError.requestFailed(statusCode, message, _, response) {
            #expect(statusCode == 403)
            #expect(message == "forbidden")
            #expect(response?.code == "FORBIDDEN")
        }

        let paths = requests.withLock { $0.compactMap(\.url?.path) }
        #expect(paths == ["/protected", "/api/auth/get-session", "/protected"])
        let authorizations = requests.withLock { $0.map { $0.value(forHTTPHeaderField: "Authorization") } }
        #expect(authorizations == ["Bearer current-token", "Bearer current-token", "Bearer refreshed-token"])
    }
}
