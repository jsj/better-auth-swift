import Foundation

struct BetterAuthSessionMaterializer: Sendable {
    let context: BetterAuthSessionContext

    func materializeSession(token: String, fallbackUser: TwoFactorUser) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network.get(path: context.configuration.endpoints.currentSessionPath,
                                                                       accessToken: token)
        guard session.user.id == fallbackUser.id else {
            context.logger?.error("Materialized session user did not match expected fallback user")
            throw BetterAuthError.invalidResponse
        }
        return BetterAuthSession(session: session.session,
                                 user: .init(id: session.user.id,
                                             email: session.user.email ?? fallbackUser.email,
                                             name: session.user.name ?? fallbackUser.name,
                                             username: session.user.username ?? fallbackUser.username,
                                             displayUsername: session.user.displayUsername ?? fallbackUser.displayUsername))
    }

    func materializeSession(token: String,
                            fallbackUser: BetterAuthSession.User) async throws -> BetterAuthSession
    {
        let session: BetterAuthSession = try await context.network.get(path: context.configuration.endpoints.currentSessionPath,
                                                                       accessToken: token)
        guard session.user.id == fallbackUser.id else {
            context.logger?.error("Materialized session user did not match expected fallback user")
            throw BetterAuthError.invalidResponse
        }
        return BetterAuthSession(session: session.session,
                                 user: session.user.merged(with: fallbackUser))
    }
}

struct BetterAuthSessionBootstrapService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay

    func loadStoredSession() throws -> BetterAuthSession? {
        try context.sessionService.loadStoredSession()
    }

    func applyRestoredSession(_ session: BetterAuthSession?) throws {
        context.state.replaceCurrentSession(session)
        context.logger?.debug("Session restored: \(session != nil ? "found" : "none")")
        context.state.emit(.initialSession,
                           session: session,
                           transition: BetterAuthSessionTransition(phase: session == nil ? .unauthenticated : .authenticated))
    }

    func restoreSession() throws -> BetterAuthSession? {
        let session = try loadStoredSession()
        try applyRestoredSession(session)
        return session
    }

    func restoreSessionOnLaunch(refreshSession: @Sendable () async throws -> BetterAuthSession) async throws -> BetterAuthRestoreResult {
        let source: BetterAuthRestoreSource
        if context.state.currentSession != nil {
            source = .memory
        } else {
            do {
                _ = try restoreSession()
            } catch {
                try relay.clearSession(event: .signedOut)
                return .cleared(.storageFailure)
            }
            source = .keychain
        }

        guard let current = context.state.currentSession else { return .noStoredSession }
        guard current.needsRefresh(clockSkew: context.configuration.auth.clockSkew) else {
            return .restored(current, source: source, refresh: .notNeeded)
        }

        do {
            let refreshed = try await refreshSession()
            return .restored(refreshed, source: source, refresh: .refreshed)
        } catch {
            if relay.shouldClearSession(for: error) {
                return .cleared(relay.clearReason(for: error))
            }
            return .restored(current, source: source, refresh: .deferred)
        }
    }

    func restoreOrRefreshSession(restoreSession: @Sendable () throws -> BetterAuthSession?,
                                 refreshSession: @Sendable () async throws -> BetterAuthSession) async throws -> BetterAuthSession?
    {
        if context.state.currentSession == nil {
            do { _ = try restoreSession() } catch {
                try relay.clearSession(event: .signedOut)
                throw error
            }
        }
        guard let current = context.state.currentSession else { return nil }
        if current.needsRefresh(clockSkew: context.configuration.auth.clockSkew) {
            do { return try await refreshSession() } catch {
                if relay.shouldClearSession(for: error) { try relay.clearSession(event: .sessionExpired) }
                throw error
            }
        }
        return current
    }

    func fetchCurrentSession() async throws -> BetterAuthSession {
        let existingToken = context.state.currentSession?.session.accessToken
        do {
            let session = try await context.refreshService.fetchCurrentSession(accessToken: existingToken)
            try relay.setSession(session, event: .tokenRefreshed)
            return session
        } catch {
            if relay.shouldClearSession(for: error) { try relay.clearSession(event: .sessionExpired) }
            throw error
        }
    }
}

struct BetterAuthSessionAdministrationService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay

    func listSessions(accessToken: String?) async throws -> [BetterAuthSessionListEntry] {
        try await context.network.get(path: context.configuration.endpoints.listSessionsPath,
                                      accessToken: accessToken)
    }

    func listDeviceSessions(accessToken: String?) async throws -> [BetterAuthDeviceSession] {
        try await context.network.get(path: context.configuration.endpoints.listDeviceSessionsPath,
                                      accessToken: accessToken)
    }

    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest,
                                accessToken: String?) async throws -> BetterAuthSession
    {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.setActiveDeviceSessionPath,
                  body: payload,
                  accessToken: accessToken)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest,
                             accessToken: String?,
                             currentAccessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.revokeDeviceSessionPath,
                  body: payload,
                  accessToken: accessToken)
        if payload.sessionToken == currentAccessToken {
            try relay.clearSession(event: .signedOut)
        }
        return response.status
    }

    func getSessionJWT(accessToken: String?) async throws -> BetterAuthJWT {
        try await context.network.get(path: context.configuration.endpoints.sessionJWTPath,
                                      accessToken: accessToken)
    }

    func getJWKS() async throws -> BetterAuthJWKS {
        try await context.network.get(path: context.configuration.endpoints.jwksPath,
                                      accessToken: nil)
    }

    func revokeSession(token: String, accessToken: String?, currentAccessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.revokeSessionPath,
                  body: RevokeSessionRequest(token: token),
                  accessToken: accessToken)
        if token == currentAccessToken {
            try relay.clearSession(event: .signedOut)
        }
        return response.status
    }

    func revokeSessions(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.revokeSessionsPath,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func revokeOtherSessions(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.revokeOtherSessionsPath,
                  accessToken: accessToken)
        return response.status
    }

    func signOut(remotely: Bool, accessToken: String?) async throws {
        if remotely, accessToken != nil {
            _ = try await context.network.post(path: context.configuration.endpoints.signOutPath,
                                               accessToken: accessToken) as SignOutResponse
        }
        try relay.clearSession(event: .signedOut)
    }
}

struct BetterAuthPasskeyService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init(),
                                    accessToken: String?) async throws -> PasskeyRegistrationOptions
    {
        try await context.network.get(path: context.configuration.endpoints.passkeyRegisterOptionsPath,
                                      queryItems: [URLQueryItem(name: "name", value: request.name),
                                                   URLQueryItem(name: "authenticatorAttachment",
                                                                value: request.authenticatorAttachment)],
                                      accessToken: accessToken)
    }

    func passkeyAuthenticateOptions(accessToken: String?) async throws -> PasskeyAuthenticationOptions {
        try await context.network.get(path: context.configuration.endpoints.passkeyAuthenticateOptionsPath,
                                      accessToken: accessToken)
    }

    func registerPasskey(_ payload: PasskeyRegistrationRequest, accessToken: String?) async throws -> Passkey {
        try await context.network.post(path: context.configuration.endpoints.passkeyRegisterPath,
                                       body: payload,
                                       accessToken: accessToken)
    }

    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.passkeyAuthenticatePath,
                  body: payload,
                  accessToken: nil)
        if let session = response.materializedSession {
            try relay.setSession(session, event: .signedIn)
            return session
        }
        if let signedIn = response.signedIn {
            let session = try await materializer.materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try relay.setSession(session, event: .signedIn)
            return session
        }
        throw BetterAuthError.invalidResponse
    }

    func listPasskeys(accessToken: String?) async throws -> [Passkey] {
        try await context.network.get(path: context.configuration.endpoints.listPasskeysPath,
                                      accessToken: accessToken)
    }

    func updatePasskey(_ payload: UpdatePasskeyRequest, accessToken: String?) async throws -> Passkey {
        let response: UpdatePasskeyResponse = try await context.network
            .post(path: context.configuration.endpoints.updatePasskeyPath,
                  body: payload,
                  accessToken: accessToken)
        return response.passkey
    }

    func deletePasskey(_ payload: DeletePasskeyRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.deletePasskeyPath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }
}

struct BetterAuthOneTimeCodeService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func requestMagicLink(_ payload: MagicLinkRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.magicLinkSignInPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func verifyMagicLink(_ payload: MagicLinkVerifyRequest) async throws -> MagicLinkVerificationResult {
        let result: MagicLinkVerificationResult = try await context.network
            .get(path: context.configuration.endpoints.magicLinkVerifyPath,
                 queryItems: [URLQueryItem(name: "token", value: payload.token),
                              URLQueryItem(name: "callbackURL", value: payload.callbackURL),
                              URLQueryItem(name: "newUserCallbackURL", value: payload.newUserCallbackURL),
                              URLQueryItem(name: "errorCallbackURL", value: payload.errorCallbackURL)],
                 accessToken: nil)
        if case let .signedIn(session) = result {
            try relay.setSession(session, event: .signedIn)
        }
        return result
    }

    func requestEmailOTP(_ payload: EmailOTPRequest) async throws -> Bool {
        let response: EmailOTPRequestResponse = try await context.network
            .post(path: context.configuration.endpoints.emailOTPRequestPath,
                  body: payload,
                  accessToken: nil)
        return response.success
    }

    func signInWithEmailOTP(_ payload: EmailOTPSignInRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.emailOTPSignInPath,
                  body: payload,
                  accessToken: nil)
        if let session = response.materializedSession {
            try relay.setSession(session, event: .signedIn)
            return session
        }
        if let signedIn = response.signedIn {
            let session = try await materializer.materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try relay.setSession(session, event: .signedIn)
            return session
        }
        throw BetterAuthError.invalidResponse
    }

    func verifyEmailOTP(_ payload: EmailOTPVerifyRequest,
                        currentSession: BetterAuthSession?) async throws -> EmailOTPVerifyResult
    {
        let result: EmailOTPVerifyResult = try await context.network
            .post(path: context.configuration.endpoints.emailOTPVerifyPath,
                  body: payload,
                  accessToken: nil)
        if case let .signedIn(session) = result {
            try relay.setSession(session, event: .signedIn)
        } else if case let .verified(user) = result, let currentSession, currentSession.user.id == user.id {
            try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                   user: currentSession.user.merged(with: user)),
                                 event: .userUpdated)
        }
        return result
    }

    func requestPhoneOTP(_ payload: PhoneOTPRequest) async throws -> Bool {
        let response: PhoneOTPRequestResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTPRequestPath,
                  body: payload,
                  accessToken: nil)
        return response.success ?? response.status ?? true
    }

    func verifyPhoneNumber(_ payload: PhoneOTPVerifyRequest,
                           accessToken: String?,
                           currentSession: BetterAuthSession?) async throws -> PhoneOTPVerifyResponse
    {
        let response: PhoneOTPVerifyResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTPVerifyPath,
                  body: payload,
                  accessToken: accessToken)
        if let token = response.token, let user = response.user {
            let twoFactorUser = TwoFactorUser(id: user.id,
                                              email: user.email,
                                              name: user.name,
                                              username: user.username,
                                              displayUsername: user.displayUsername,
                                              twoFactorEnabled: false)
            let session = try await materializer.materializeSession(token: token, fallbackUser: twoFactorUser)
            try relay.setSession(session, event: .signedIn)
        } else if let user = response.user, let currentSession, currentSession.user.id == user.id {
            try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                   user: currentSession.user.merged(with: user)),
                                 event: .userUpdated)
        }
        return response
    }

    func signInWithPhoneOTP(_ payload: PhoneOTPSignInRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.phoneOTPSignInPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        try relay.setSession(session, event: .signedIn)
        return session
    }
}

struct BetterAuthTwoFactorService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func enableTwoFactor(_ payload: TwoFactorEnableRequest,
                         accessToken: String?) async throws -> TwoFactorEnableResponse
    {
        try await context.network.post(path: context.configuration.endpoints.twoFactorEnablePath,
                                       body: payload,
                                       accessToken: accessToken)
    }

    func verifyTwoFactorTOTP(_ payload: TwoFactorVerifyTOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorVerifyTOTPPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func sendTwoFactorOTP(_ payload: TwoFactorSendOTPRequest = .init()) async throws -> Bool {
        let response: TwoFactorChallengeStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorSendOTPPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func verifyTwoFactorOTP(_ payload: TwoFactorVerifyOTPRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorVerifyOTPPath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func verifyTwoFactorRecoveryCode(_ payload: TwoFactorVerifyBackupCodeRequest) async throws -> BetterAuthSession {
        let response: TwoFactorSessionResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorVerifyBackupCodePath,
                  body: payload,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func disableTwoFactor(_ payload: TwoFactorDisableRequest,
                          accessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorDisablePath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func generateTwoFactorRecoveryCodes(password: String,
                                        accessToken: String?) async throws -> [String]
    {
        struct Request: Encodable, Sendable { let password: String }
        let response: TwoFactorGenerateBackupCodesResponse = try await context.network
            .post(path: context.configuration.endpoints.twoFactorGenerateBackupCodesPath,
                  body: Request(password: password),
                  accessToken: accessToken)
        return response.backupCodes
    }
}

struct BetterAuthPrimaryAuthService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func signUpWithEmail(_ payload: EmailSignUpRequest) async throws -> EmailSignUpResult {
        let result: EmailSignUpResult = try await context.network
            .post(path: context.configuration.endpoints.emailSignUpPath,
                  body: payload,
                  accessToken: nil)
        if case let .signedIn(session) = result {
            try relay.setSession(session, event: .signedIn)
        }
        return result
    }

    func signInWithEmail(_ payload: EmailSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.emailSignInPath,
                  body: payload,
                  accessToken: nil)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func isUsernameAvailable(_ payload: UsernameAvailabilityRequest) async throws -> Bool {
        let response: UsernameAvailabilityResponse = try await context.network
            .post(path: context.configuration.endpoints.usernameAvailabilityPath,
                  body: payload,
                  accessToken: nil)
        return response.available
    }

    func signInWithUsername(_ payload: UsernameSignInRequest) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.usernameSignInPath,
                  body: payload,
                  accessToken: nil)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func signInWithApple(_ payload: AppleNativeSignInPayload) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.nativeAppleSignInPath,
                  body: payload,
                  accessToken: nil)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func signInWithSocial(_ payload: SocialSignInRequest) async throws -> SocialSignInResult {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.socialSignInPath,
                  body: payload,
                  accessToken: nil)

        if let session = response.materializedSession {
            try relay.setSession(session, event: .signedIn)
            let signedIn = SocialSignInSuccessResponse(redirect: response.redirect,
                                                       token: session.session.accessToken,
                                                       url: response.url,
                                                       user: session.user)
            return .signedIn(signedIn)
        }

        if let signedIn = response.signedIn {
            let session = try await materializer.materializeSession(token: signedIn.token, fallbackUser: signedIn.user)
            try relay.setSession(session, event: .signedIn)
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
            .post(path: context.configuration.endpoints.anonymousSignInPath,
                  accessToken: nil)
        let session = try await materializer.materializeSession(token: response.token, fallbackUser: response.user)
        try relay.setSession(session, event: .signedIn)
        return session
    }

    func deleteAnonymousUser(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.deleteAnonymousUserPath,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func deleteUser(_ payload: DeleteUserRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.deleteUserPath,
                  body: payload,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func reauthenticate(password: String, currentSession: BetterAuthSession?) async throws -> Bool {
        guard let currentSession else { throw BetterAuthError.missingSession }
        guard let email = currentSession.user.email else { throw BetterAuthError.missingSession }
        let verificationSession: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.emailSignInPath,
                  body: EmailSignInRequest(email: email, password: password),
                  accessToken: nil)
        guard verificationSession.user.id == currentSession.user.id else {
            throw BetterAuthError.invalidResponse
        }
        do {
            let _: BetterAuthStatusResponse = try await context.network
                .post(path: context.configuration.endpoints.revokeSessionPath,
                      body: RevokeSessionRequest(token: verificationSession.session.id),
                      accessToken: verificationSession.session.accessToken)
        } catch {
        }
        return true
    }

    func requestPasswordReset(_ payload: ForgotPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.forgotPasswordPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }

    func resetPassword(_ payload: ResetPasswordRequest) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.resetPasswordPath,
                  body: payload,
                  accessToken: nil)
        return response.status
    }
}

struct BetterAuthProfileService: Sendable {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    func sendVerificationEmail(_ payload: SendVerificationEmailRequest = .init(),
                               accessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.sendVerificationEmailPath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func verifyEmail(_ payload: VerifyEmailRequest) async throws -> VerifyEmailResult {
        let result: VerifyEmailResult = try await context.network
            .get(path: context.configuration.endpoints.verifyEmailPath,
                 queryItems: [URLQueryItem(name: "token", value: payload.token)],
                 accessToken: nil)
        if case let .signedIn(session) = result {
            try relay.setSession(session, event: .signedIn)
        }
        return result
    }

    func changeEmail(_ payload: ChangeEmailRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.changeEmailPath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }

    func updateUser(_ payload: UpdateUserRequest, currentSession: BetterAuthSession?) async throws -> UpdateUserResponse {
        let response = try await context.userAccountService.updateUser(payload,
                                                                       accessToken: currentSession?.session.accessToken)
        if let user = response.user, let currentSession {
            try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                   user: currentSession.user.merged(with: user)),
                                 event: .userUpdated)
        }
        return response
    }

    func changePassword(_ payload: ChangePasswordRequest,
                        currentSession: BetterAuthSession?) async throws -> ChangePasswordResponse
    {
        let response = try await context.userAccountService.changePassword(payload,
                                                                           accessToken: currentSession?.session.accessToken)
        if payload.revokeOtherSessions == true, let session = response.session {
            try relay.setSession(session, event: .tokenRefreshed)
        } else if payload.revokeOtherSessions == true, let rotatedToken = response.token {
            let materializedSession: BetterAuthSession = try await context.network
                .get(path: context.configuration.endpoints.currentSessionPath,
                     accessToken: rotatedToken)
            try relay.setSession(materializedSession, event: .tokenRefreshed)
        } else if let currentSession {
            try relay.setSession(BetterAuthSession(session: currentSession.session,
                                                   user: currentSession.user.merged(with: response.user)),
                                 event: .userUpdated)
        }
        return response
    }

    func listLinkedAccounts(accessToken: String?) async throws -> [LinkedAccount] {
        try await context.network.get(path: context.configuration.endpoints.listLinkedAccountsPath,
                                      accessToken: accessToken)
    }

    func linkSocialAccount(_ payload: LinkSocialAccountRequest,
                           accessToken: String?) async throws -> LinkSocialAccountResponse
    {
        try await context.network.post(path: context.configuration.endpoints.linkSocialAccountPath,
                                       body: payload,
                                       accessToken: accessToken)
    }
}

struct BetterAuthOAuthService: Sendable {
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
        try relay.setSession(session, event: .signedIn)
        return session
    }
}
