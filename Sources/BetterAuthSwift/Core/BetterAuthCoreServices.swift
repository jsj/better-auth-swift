import Foundation

protocol BetterAuthTransporting: Sendable {
    func post<Response: Decodable>(path: String,
                                   body: some Encodable & Sendable,
                                   accessToken: String?) async throws -> Response
    func post<Response: Decodable>(path: String,
                                   accessToken: String?) async throws -> Response
    func get<Response: Decodable>(path: String,
                                  accessToken: String?) async throws -> Response
    func get<Response: Decodable>(path: String,
                                  queryItems: [URLQueryItem],
                                  accessToken: String?) async throws -> Response
}

protocol BetterAuthSessionStoring: Sendable {
    func loadStoredSession() throws -> BetterAuthSession?
    func persist(_ session: BetterAuthSession?) throws
}

struct BetterAuthSessionService: BetterAuthSessionStoring {
    let configuration: BetterAuthConfiguration
    let sessionStore: BetterAuthSessionStore

    func loadStoredSession() throws -> BetterAuthSession? {
        try sessionStore.loadSession(for: configuration.storage.key)
    }

    func persist(_ session: BetterAuthSession?) throws {
        if let session {
            try sessionStore.saveSession(session, for: configuration.storage.key)
        } else {
            try sessionStore.clearSession(for: configuration.storage.key)
        }
    }
}

struct BetterAuthSessionRefreshService {
    let configuration: BetterAuthConfiguration
    let network: any BetterAuthTransporting

    func refresh(using existingSession: BetterAuthSession) async throws -> BetterAuthSession {
        if let refreshToken = existingSession.session.refreshToken {
            struct RefreshPayload: Encodable, Sendable { let refreshToken: String }
            return try await network.post(path: configuration.endpoints.session.sessionRefreshPath,
                                          body: RefreshPayload(refreshToken: refreshToken),
                                          accessToken: existingSession.session.accessToken)
        }
        return try await network.post(path: configuration.endpoints.session.sessionRefreshPath,
                                      accessToken: existingSession.session.accessToken)
    }

    func fetchCurrentSession(accessToken: String?) async throws -> BetterAuthSession {
        try await network.get(path: configuration.endpoints.session.currentSessionPath,
                              accessToken: accessToken)
    }
}

struct BetterAuthAuthFlowService {
    let configuration: BetterAuthConfiguration
    let network: any BetterAuthTransporting

    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await network.post(path: configuration.endpoints.oauth.genericOAuthSignInPath, body: payload,
                               accessToken: nil)
    }

    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest,
                          accessToken: String?) async throws -> GenericOAuthAuthorizationResponse
    {
        try await network.post(path: configuration.endpoints.oauth.genericOAuthLinkPath,
                               body: payload,
                               accessToken: accessToken)
    }
}

struct BetterAuthUserAccountService {
    let configuration: BetterAuthConfiguration
    let network: any BetterAuthTransporting

    func updateUser(_ payload: UpdateUserRequest,
                    accessToken: String?) async throws -> UpdateUserResponse
    {
        try await network.post(path: configuration.endpoints.user.updateUserPath,
                               body: payload,
                               accessToken: accessToken)
    }

    func changePassword(_ payload: ChangePasswordRequest,
                        accessToken: String?) async throws -> ChangePasswordResponse
    {
        try await network.post(path: configuration.endpoints.user.changePasswordPath,
                               body: payload,
                               accessToken: accessToken)
    }
}
