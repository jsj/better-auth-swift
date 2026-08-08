import BetterAuthAnonymous
import BetterAuthEmailPassword
import BetterAuthUsername
import Foundation
import Testing
@testable import BetterAuth

private enum LiveBetterAuthContract {
    static let environment = ProcessInfo.processInfo.environment
    static let baseURL = environment["BETTER_AUTH_CONTRACT_BASE_URL"].flatMap(URL.init(string:))
    static let email = nonEmptyEnvironmentValue("BETTER_AUTH_CONTRACT_EMAIL")
    static let password = nonEmptyEnvironmentValue("BETTER_AUTH_CONTRACT_PASSWORD")
    static let username = nonEmptyEnvironmentValue("BETTER_AUTH_CONTRACT_USERNAME")
    static let usernamePassword = nonEmptyEnvironmentValue("BETTER_AUTH_CONTRACT_USERNAME_PASSWORD")
    static let expectsJWKS = environment["BETTER_AUTH_CONTRACT_EXPECT_JWKS"] == "true"
    static let supportsAnonymous = environment["BETTER_AUTH_CONTRACT_SUPPORTS_ANONYMOUS"] == "true"
    static let provisionWithFixtures = environment["BETTER_AUTH_CONTRACT_PROVISION_WITH_FIXTURES"] == "true"
    static var requestOrigin: String? {
        environment["BETTER_AUTH_CONTRACT_REQUEST_ORIGIN"] ??
            baseURL?.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    static let isConfigured = baseURL != nil && email != nil && password != nil
    static let usernameIsConfigured = baseURL != nil && username != nil && usernamePassword != nil
    static let jwksIsConfigured = baseURL != nil && expectsJWKS
    static let anonymousIsConfigured = baseURL != nil && supportsAnonymous
    static var fixtureCaptureURL: URL? {
        if let configured = environment["BETTER_AUTH_CONTRACT_FIXTURE_CAPTURE_URL"].flatMap(URL.init(string:)) {
            return configured
        }
        return baseURL?.appending(path: "api/fixtures/captures")
    }

    static func nonEmptyEnvironmentValue(_ key: String) -> String? {
        environment[key].flatMap { value in
            value.isEmpty ? nil : value
        }
    }

    static func makeClient(storageKey: String = "better-auth.contract-test") throws -> BetterAuthClient {
        BetterAuthClient(configuration: BetterAuthConfiguration(baseURL: try #require(baseURL),
                                                                storage: .init(key: storageKey),
                                                                requestOrigin: requestOrigin),
                         sessionStore: InMemorySessionStore(),
                         transport: URLSessionTransport(session: makeIsolatedURLSession()),
                         modules: [BetterAuthAnonymousModule(),
                                   BetterAuthEmailPasswordModule(),
                                   BetterAuthUsernameModule()])
    }

    static func makeIsolatedURLSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        return URLSession(configuration: configuration)
    }

    static func signInWithProvisioningIfNeeded(client: BetterAuthClient,
                                               email: String,
                                               password: String) async throws -> BetterAuthSession
    {
        do {
            return try await client.requireEmailPassword().signIn(.init(email: email, password: password))
        } catch {
            guard provisionWithFixtures else {
                throw error
            }
        }

        let fixtures = FixtureCaptureClient(origin: requestOrigin)
        try await fixtures.signUp(email: email,
                                  password: password,
                                  baseURL: try #require(baseURL))
        let token = try await fixtures.verificationToken(for: email,
                                                         captureURL: try #require(fixtureCaptureURL))
        _ = try await client.auth.verifyEmail(.init(token: token))
        try await client.auth.signOut(remotely: true)
        return try await client.requireEmailPassword().signIn(.init(email: email, password: password))
    }
}

@Suite(.serialized)
struct LiveBetterAuthContractTests {
    @Test(.enabled(if: LiveBetterAuthContract.isConfigured))
    func emailSignInSessionLifecycleAndRemoteSignOutAgainstRealServer() async throws {
        let client = try LiveBetterAuthContract.makeClient(storageKey: "better-auth.contract.email")

        let session = try await LiveBetterAuthContract.signInWithProvisioningIfNeeded(client: client,
                                                                                      email: try #require(LiveBetterAuthContract
                                                                                          .email),
                                                                                      password: try #require(LiveBetterAuthContract
                                                                                          .password))
        #expect(session.session.accessToken.isEmpty == false)
        #expect(session.user.email == LiveBetterAuthContract.email)

        let fetched = try await client.auth.fetchCurrentSession()
        #expect(fetched.user.id == session.user.id)
        #expect(fetched.session.accessToken.isEmpty == false)

        let refreshedIfNeeded = try await client.auth.refreshSessionIfNeeded()
        #expect(refreshedIfNeeded.user.id == session.user.id)

        let requestFetched: BetterAuthSession = try await client.requests
            .sendJSON(path: client.configuration.endpoints.session.currentSessionPath)
        #expect(requestFetched.user.id == session.user.id)

        let listedSessions = try await client.auth.listSessions()
        #expect(listedSessions.isEmpty == false)

        try await client.auth.signOut(remotely: true)
        #expect(await client.auth.currentSession() == nil)
    }

    @Test(.enabled(if: LiveBetterAuthContract.usernameIsConfigured))
    func usernameSignInFetchSessionAndRemoteSignOutAgainstRealServer() async throws {
        let client = try LiveBetterAuthContract.makeClient(storageKey: "better-auth.contract.username")

        let session = try await client.requireUsername().signIn(.init(username: try #require(LiveBetterAuthContract
                                                                          .username),
            password: try #require(LiveBetterAuthContract
                .usernamePassword)))
        #expect(session.session.accessToken.isEmpty == false)

        let fetched = try await client.auth.fetchCurrentSession()
        #expect(fetched.user.id == session.user.id)

        try await client.auth.signOut(remotely: true)
        #expect(await client.auth.currentSession() == nil)
    }

    @Test(.enabled(if: LiveBetterAuthContract.jwksIsConfigured))
    func jwksAgainstRealServer() async throws {
        let client = try LiveBetterAuthContract.makeClient(storageKey: "better-auth.contract.jwks")

        let jwks = try await client.auth.getJWKS()
        #expect(jwks.keys.isEmpty == false)
    }

    @Test(.enabled(if: LiveBetterAuthContract.anonymousIsConfigured))
    func anonymousSignInAndDeleteAgainstRealServer() async throws {
        let client = try LiveBetterAuthContract.makeClient(storageKey: "better-auth.contract.anonymous")

        let session = try await client.requireAnonymous().signIn()
        #expect(session.session.accessToken.isEmpty == false)

        let deleted = try await client.requireAnonymous().deleteUser()
        #expect(deleted)
        #expect(await client.auth.currentSession() == nil)
    }
}

private struct FixtureCaptureClient {
    let origin: String?

    func signUp(email: String, password: String, baseURL: URL) async throws {
        let url = baseURL.appending(path: "api/auth/email/sign-up")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let origin {
            request.setValue(origin, forHTTPHeaderField: "Origin")
        }
        request.httpBody = try JSONEncoder().encode(FixtureEmailSignUp(email: email,
                                                                       password: password,
                                                                       name: "Better Auth Contract User"))

        let (_, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200 ..< 300).contains(httpResponse.statusCode)
        else {
            throw BetterAuthError.invalidResponse
        }
    }

    func verificationToken(for email: String, captureURL: URL) async throws -> String {
        let deadline = Date().addingTimeInterval(10)
        var lastError: (any Error)?

        repeat {
            do {
                if let token = try await fetchVerificationToken(for: email, captureURL: captureURL) {
                    return token
                }
            } catch {
                lastError = error
            }

            try await Task.sleep(nanoseconds: 500_000_000)
        } while Date() < deadline

        if let lastError {
            throw lastError
        }
        throw BetterAuthError.invalidResponse
    }

    private func fetchVerificationToken(for email: String, captureURL: URL) async throws -> String? {
        let (data, response) = try await URLSession.shared.data(from: captureURL)
        guard let httpResponse = response as? HTTPURLResponse,
              (200 ..< 300).contains(httpResponse.statusCode)
        else {
            throw BetterAuthError.invalidResponse
        }

        let captures = try JSONDecoder().decode(FixtureCaptureResponse.self, from: data).captures
        return captures.first { capture in
            capture.channel == "email-verification" && capture.email?.lowercased() == email.lowercased()
        }?.token
    }
}

private struct FixtureCaptureResponse: Decodable {
    let captures: [FixtureCapture]
}

private struct FixtureCapture: Decodable {
    let channel: String
    let token: String
    let email: String?
}

private struct FixtureEmailSignUp: Encodable {
    let email: String
    let password: String
    let name: String
}
