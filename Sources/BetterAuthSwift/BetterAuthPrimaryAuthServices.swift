import Foundation

struct BetterAuthPrimaryAuthService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        let result: EmailSignUpResult = try await context.network
            .post(path: context.configuration.endpoints.auth.emailSignUpPath,
                  body: payload,
                  accessToken: nil)
        if case let .signedIn(session) = result {
            _ = try relay.setSession(session, event: .signedIn)
        }
        return result
    }

    func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.auth.emailSignInPath,
                  body: payload,
                  accessToken: nil)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        let response: UsernameAvailabilityResponse = try await context.network
            .post(path: context.configuration.endpoints.auth.usernameAvailabilityPath,
                  body: payload,
                  accessToken: nil)
        return response.available
    }

    func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.auth.usernameSignInPath,
                  body: payload,
                  accessToken: nil)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.auth.nativeAppleSignInPath,
                  body: payload,
                  accessToken: nil)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.auth.socialSignInPath,
                  body: payload,
                  accessToken: nil)

        if let session = response.materializedSession {
            _ = try relay.setSession(session, event: .signedIn)
            let signedIn = SocialSignInSuccessResponse(redirect: response.redirect,
                                                       token: session.session.accessToken,
                                                       url: response.url,
                                                       user: session.user)
            return .signedIn(signedIn)
        }

        if let signedIn = response.signedIn {
            let session = try await materializer.materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            _ = try relay.setSession(session, event: .signedIn)
            return .signedIn(signedIn)
        }

        switch response.authorizationURL {
        case let .success(authorizationURL):
            return .authorizationURL(authorizationURL)

        case let .failure(error):
            throw error
        }
    }

    func signInAnonymously() async throws -> BetterAuthSession {
        let response: SignedInTokenResponse = try await context.network
            .post(path: context.configuration.endpoints.auth.anonymousSignInPath,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }

    func deleteAnonymousUser(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.user.deleteAnonymousUserPath,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func deleteUser(_ payload: DeleteUserRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.user.deleteUserPath,
                  body: payload,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func reauthenticate(password: String, currentSession: BetterAuthSession?) async throws -> Bool {
        guard let currentSession else { throw BetterAuthError.missingSession }
        guard let email = currentSession.user.email else { throw BetterAuthError.missingSession }
        let verificationSession: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.auth.emailSignInPath,
                  body: EmailSignInRequest(email: email, password: password),
                  accessToken: nil)
        guard verificationSession.user.id == currentSession.user.id else {
            throw BetterAuthError.invalidResponse
        }
        do {
            let _: BetterAuthStatusResponse = try await context.network
                .post(path: context.configuration.endpoints.session.revokeSessionPath,
                      body: RevokeSessionRequest(token: verificationSession.session.id),
                      accessToken: verificationSession.session.accessToken)
        } catch {
            context.logger?.warning("Failed to revoke temporary reauthentication session: \(error)")
        }
        return true
    }

    func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.auth.forgotPasswordPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.auth.resetPasswordPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }
}

struct BetterAuthProfileService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

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
            _ = try relay.setSession(session, event: .signedIn)
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
        if let user = response.user, let currentSession {
            _ = try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                       user: currentSession.user.merged(with: user)),
                                     event: .userUpdated)
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
            _ = try relay.setSession(session, event: .tokenRefreshed)
        } else if payload.revokeOtherSessions == true, let rotatedToken = response.token {
            let materializedSession: BetterAuthSession = try await context.network
                .get(path: context.configuration.endpoints.session.currentSessionPath,
                     accessToken: rotatedToken)
            _ = try relay.setSession(materializedSession, event: .tokenRefreshed)
        } else if let currentSession {
            _ = try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                       user: currentSession.user.merged(with: response.user)),
                                     event: .userUpdated)
        }
        return response
    }

    func listLinkedAccounts(accessToken: String?) async throws -> [LinkedAccount] {
        try await context.network.get(path: context.configuration.endpoints.oauth.listLinkedAccountsPath,
                                      accessToken: accessToken)
    }

    func linkSocialAccount(_ payload: LinkSocialAccountRequest,
                           accessToken: String?) async throws -> LinkSocialAccountResponse
    {
        try await context.network.post(path: context.configuration.endpoints.oauth.linkSocialAccountPath,
                                       body: payload,
                                       accessToken: accessToken)
    }
}

struct BetterAuthOAuthService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay

    func beginGenericOAuth(_ payload: GenericOAuthSignInRequest) async throws -> GenericOAuthAuthorizationResponse {
        try await context.authFlowService.beginGenericOAuth(payload)
    }

    func linkGenericOAuth(_ payload: GenericOAuthSignInRequest,
                          accessToken: String?) async throws -> GenericOAuthAuthorizationResponse
    {
        try await context.authFlowService.linkGenericOAuth(payload, accessToken: accessToken)
    }

    func completeGenericOAuth(_ payload: GenericOAuthCallbackRequest,
                              accessToken: String?) async throws -> BetterAuthSession
    {
        let session: BetterAuthSession = try await context.network
            .get(path: context.callbackHandler.oauthCallbackPath(for: payload),
                 accessToken: accessToken)
        _ = try relay.setSession(session, event: .signedIn)
        return session
    }
}
