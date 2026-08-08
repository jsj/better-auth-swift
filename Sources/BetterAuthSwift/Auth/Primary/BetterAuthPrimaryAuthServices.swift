import Foundation

struct BetterAuthProfileService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer
    private var sessionResults: BetterAuthSessionResultHandler {
        BetterAuthSessionResultHandler(relay: relay, materializer: materializer)
    }

    func deleteUser(_ payload: DeleteUserRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.user.deleteUserPath,
                  body: payload,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init(),
                               accessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.user.sendVerificationEmailPath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        let result: VerifyEmailResult = try await context.network
            .get(path: context.configuration.endpoints.user.verifyEmailPath,
                 queryItems: [URLQueryItem(name: "token", value: payload.token)],
                 accessToken: nil)
        if case let .signedIn(session) = result {
            try await sessionResults.apply(.signedIn(session))
        }
        return result
    }

    func changeEmail(_ payload: ChangeEmailRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.user.changeEmailPath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func updateUser(_ payload: UpdateUserRequest,
                    currentSession: BetterAuthSession?) async throws -> UpdateUserResponse
    {
        let response = try await context.userAccountService.updateUser(payload,
                                                                       accessToken: currentSession?.session.accessToken)
        if let user = response.user {
            try await sessionResults.apply(.updatedUser(user, currentSession: currentSession))
        }
        return response
    }

    func changePassword(_ payload: ChangePasswordRequest,
                        currentSession: BetterAuthSession?) async throws -> ChangePasswordResponse
    {
        let response = try await context.userAccountService.changePassword(payload,
                                                                           accessToken: currentSession?.session
                                                                               .accessToken)
        if payload.revokeOtherSessions == true, let session = response.session {
            try await sessionResults.apply(.refreshed(session))
        } else if payload.revokeOtherSessions == true, let rotatedToken = response.token {
            let materializedSession: BetterAuthSession = try await context.network
                .get(path: context.configuration.endpoints.session.currentSessionPath,
                     accessToken: rotatedToken)
            try await sessionResults.apply(.refreshed(materializedSession))
        } else {
            try await sessionResults.apply(.updatedUser(response.user, currentSession: currentSession))
        }
        return response
    }
}
