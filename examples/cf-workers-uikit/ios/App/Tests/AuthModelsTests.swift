import BetterAuth
import Foundation
import os
import Testing
@testable import BetterAuthUIKitExample

struct AuthModelsTests {
    @Test
    func payloadFieldsAreAccessible() {
        let payload = AppleNativeSignInPayload(token: "abcdefghijklmnopqrstuvwxyz0123456789",
                                               nonce: "nonce",
                                               authorizationCode: "authorization-code",
                                               email: "jane@example.com",
                                               givenName: "Jane",
                                               familyName: "Doe")

        #expect(payload.email == "jane@example.com")
        #expect(payload.givenName == "Jane")
        #expect(payload.familyName == "Doe")
        #expect(payload.authorizationCode == "authorization-code")
        #expect(payload.nonce == "nonce")
        #expect(payload.token == "abcdefghijklmnopqrstuvwxyz0123456789")
    }

    @Test
    func repeatAuthorizationPayloadCanOmitFirstUseProfileHints() {
        let payload = AppleNativeSignInPayload(token: "abcdefghijklmnopqrstuvwxyz0123456789",
                                               nonce: "nonce")

        #expect(payload.email == nil)
        #expect(payload.givenName == nil)
        #expect(payload.familyName == nil)
        #expect(payload.authorizationCode == nil)
        #expect(payload.nonce == "nonce")
        #expect(payload.token == "abcdefghijklmnopqrstuvwxyz0123456789")
    }

    @Test
    @MainActor
    func restorePreservesStoredSessionAndAvoidsUnauthorizedState() async throws {
        let storedSession = BetterAuthSession(session: .init(id: "stored-session",
                                                             userId: "user-1",
                                                             accessToken: "stored-token",
                                                             expiresAt: Date().addingTimeInterval(3600)),
                                              user: .init(id: "user-1", email: "jane@example.com", name: "Jane"))

        let model =
            AuthViewModel(configuration: AuthConfiguration(apiBaseURL: try #require(URL(string: "https://example.com")),
                                                           source: .infoPlist),
                          client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                                          storage: .init(key: "test-key")),
                                                   sessionStore: try configuredStore(session: storedSession),
                                                   transport: MockTransport { _ in
                                                       Issue
                                                           .record(Comment(rawValue: "Restore should not hit the network for a fresh session"))
                                                       return response(for: URLRequest(url: URL(string: "https://example.com")!),
                                                                       statusCode: 500,
                                                                       data: Data())
                                                   }))

        await model.restore()

        #expect(model.session == storedSession)
        #expect(model.statusMessage == "Session restored")
        #expect(model.isPerformingAuthAction == false)
    }

    @Test
    @MainActor
    func refreshFailureClearsVisibleSessionState() async throws {
        let staleSession = BetterAuthSession(session: .init(id: "session-stale",
                                                            userId: "user-1",
                                                            accessToken: "stale-token",
                                                            expiresAt: Date().addingTimeInterval(-60)),
                                             user: .init(id: "user-1", email: "jane@example.com", name: "Jane"))

        let model =
            AuthViewModel(configuration: AuthConfiguration(apiBaseURL: try #require(URL(string: "https://example.com")),
                                                           source: .infoPlist),
                          client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                                          storage: .init(key: "test-key")),
                                                   sessionStore: try configuredStore(session: staleSession),
                                                   transport: MockTransport { request in
                                                       #expect(request.url?.path == "/api/auth/get-session")
                                                       let body = ["code": "UNAUTHORIZED",
                                                                   "message": "expired session"]
                                                       return try response(for: request, statusCode: 401,
                                                                           data: JSONSerialization
                                                                               .data(withJSONObject: body))
                                                   }))

        model.session = staleSession
        await model.refresh()

        #expect(model.session == staleSession)
        #expect(model.statusMessage?.isEmpty == false,
                Comment(rawValue: "Expected refresh failure to surface a user-visible error"))
        #expect(model.isPerformingAuthAction == false, Comment(rawValue: "Expected refresh activity flag to reset"))
    }

    @Test
    @MainActor
    func signOutClearsVisibleSessionStateEvenWhenRemoteCallFails() async throws {
        let activeSession = BetterAuthSession(session: .init(id: "session-active",
                                                             userId: "user-1",
                                                             accessToken: "active-token",
                                                             expiresAt: Date().addingTimeInterval(3600)),
                                              user: .init(id: "user-1", email: "jane@example.com", name: "Jane"))

        let store = try configuredStore(session: activeSession)
        let model =
            AuthViewModel(configuration: AuthConfiguration(apiBaseURL: try #require(URL(string: "https://example.com")),
                                                           source: .infoPlist),
                          client: BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(URL(string: "https://example.com")),
                                                                                          storage: .init(key: "test-key")),
                                                   sessionStore: store,
                                                   transport: MockTransport { request in
                                                       #expect(request.url?.path == "/api/auth/sign-out")
                                                       #expect(request
                                                           .value(forHTTPHeaderField: "Authorization") ==
                                                           "Bearer active-token")
                                                       let body = ["code": "SERVER_ERROR",
                                                                   "message": "temporary failure"]
                                                       return try response(for: request, statusCode: 500,
                                                                           data: JSONSerialization
                                                                               .data(withJSONObject: body))
                                                   }))

        model.session = activeSession
        try await model.debugClient.auth.updateSession(activeSession)
        await model.signOut()

        #expect(model.session == nil)
        #expect(model.statusMessage?.isEmpty == false,
                Comment(rawValue: "Expected local sign-out fallback to surface status"))
        let persisted = try store.loadSession(for: "test-key")
        #expect(persisted == nil, Comment(rawValue: "Expected sign-out to clear persisted session state"))
        #expect(model.isPerformingAuthAction == false, Comment(rawValue: "Expected sign-out activity flag to reset"))
    }
}

private struct MockTransport: BetterAuthTransport {
    let handler: @Sendable (URLRequest) async throws -> (Data, URLResponse)

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await handler(request)
    }
}

private final class MockURLProtocol: URLProtocol {
    private typealias RequestHandler = @Sendable (URLRequest) throws -> (HTTPURLResponse, Data)
    private static let requestHandler = OSAllocatedUnfairLock<RequestHandler?>(initialState: nil)

    static func setRequestHandler(_ handler: RequestHandler?) {
        requestHandler.withLock { $0 = handler }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let handler = Self.requestHandler.withLock({ $0 }) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

private func configuredStore(session: BetterAuthSession) throws -> InMemorySessionStore {
    let store = InMemorySessionStore()
    try store.saveSession(session, for: "test-key")
    return store
}

private func response(for request: URLRequest, statusCode: Int, data: Data) -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: request.url ?? URL(string: "https://example.com")!,
                                   statusCode: statusCode,
                                   httpVersion: nil,
                                   headerFields: nil)!
    return (data, response)
}

private func makeURLSession() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [MockURLProtocol.self]
    return URLSession(configuration: configuration)
}

extension AuthModelsTests {
    @Test
    func workerReachabilityTreatsSuccessfulHeadResponseAsReachable() async throws {
        MockURLProtocol.setRequestHandler { request in
            #expect(request.httpMethod == "HEAD")
            let response = HTTPURLResponse(url: request.url ?? URL(string: "https://example.com")!,
                                           statusCode: 200,
                                           httpVersion: nil,
                                           headerFields: nil)!
            return (response, Data())
        }

        let service =
            AuthService(client: BetterAuthClient(baseURL: try #require(URL(string: "https://example.com"))),
                        session: makeURLSession())

        let reachable = await service.isWorkerReachable()

        #expect(reachable == true)
        MockURLProtocol.setRequestHandler(nil)
    }

    @Test
    func workerReachabilityTreatsTransportFailureAsUnreachable() async throws {
        MockURLProtocol.setRequestHandler { _ in
            throw URLError(.cannotConnectToHost)
        }

        let service =
            AuthService(client: BetterAuthClient(baseURL: try #require(URL(string: "https://example.com"))),
                        session: makeURLSession())

        let reachable = await service.isWorkerReachable()

        #expect(reachable == false)
        MockURLProtocol.setRequestHandler(nil)
    }
}
