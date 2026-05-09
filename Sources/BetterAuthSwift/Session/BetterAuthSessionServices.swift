import Foundation

struct BetterAuthSessionMaterializer {
    let context: BetterAuthSessionContext

    func materializeSession(token: String, fallbackUser: TwoFactorUser) async throws -> BetterAuthSession {
        let session: BetterAuthSession = try await context.network
            .get(path: context.configuration.endpoints.session.currentSessionPath,
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
                                             displayUsername: session.user.displayUsername ?? fallbackUser
                                                 .displayUsername))
    }

    func materializeSession(token: String,
                            fallbackUser: BetterAuthSession.User) async throws -> BetterAuthSession
    {
        let session: BetterAuthSession = try await context.network
            .get(path: context.configuration.endpoints.session.currentSessionPath,
                 accessToken: token)
        guard session.user.id == fallbackUser.id else {
            context.logger?.error("Materialized session user did not match expected fallback user")
            throw BetterAuthError.invalidResponse
        }
        return BetterAuthSession(session: session.session,
                                 user: session.user.merged(with: fallbackUser))
    }
}

struct BetterAuthSessionResultHandler {
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer

    @discardableResult
    func apply(_ outcome: BetterAuthSessionOutcome) async throws -> BetterAuthSessionOutcomeResult {
        switch outcome {
        case let .signedIn(session):
            return .signedIn(try apply(session, event: .signedIn))

        case let .refreshed(session):
            return .signedIn(try apply(session, event: .tokenRefreshed))

        case let .token(token, fallbackUser):
            let session = try await materializer.materializeSession(token: token, fallbackUser: fallbackUser)
            return .signedIn(try apply(session, event: .signedIn))

        case let .twoFactorToken(token, fallbackUser):
            let session = try await materializer.materializeSession(token: token, fallbackUser: fallbackUser)
            return .signedIn(try apply(session, event: .signedIn))

        case let .updatedUser(user, currentSession):
            guard let currentSession, currentSession.user.id == user.id else { return .unchanged }
            return .updated(try apply(BetterAuthSession(session: currentSession.session,
                                                        user: currentSession.user.merged(with: user)),
                                      event: .userUpdated))

        case .none:
            return .unchanged
        }
    }

    func appliedSession(from outcome: BetterAuthSessionOutcome) async throws -> BetterAuthSession {
        guard let session = try await apply(outcome).session else {
            throw BetterAuthError.invalidResponse
        }
        return session
    }

    private func apply(_ session: BetterAuthSession, event: AuthChangeEvent) throws -> BetterAuthSession {
        _ = try relay.setSession(session, event: event)
        return session
    }
}

enum BetterAuthSessionOutcome: Sendable {
    case signedIn(BetterAuthSession)
    case refreshed(BetterAuthSession)
    case token(token: String, fallbackUser: BetterAuthSession.User)
    case twoFactorToken(token: String, fallbackUser: TwoFactorUser)
    case updatedUser(BetterAuthSession.User, currentSession: BetterAuthSession?)
    case none
}

enum BetterAuthSessionOutcomeResult: Sendable, Equatable {
    case signedIn(BetterAuthSession)
    case updated(BetterAuthSession)
    case unchanged

    var session: BetterAuthSession? {
        switch self {
        case let .signedIn(session), let .updated(session):
            session

        case .unchanged:
            nil
        }
    }
}

struct BetterAuthSessionBootstrapService {
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
                           transition: BetterAuthSessionTransition(phase: session == nil ? .unauthenticated :
                               .authenticated))
    }

    func restoreSession() throws -> BetterAuthSession? {
        let session = try loadStoredSession()
        try applyRestoredSession(session)
        return session
    }

    func restoreSessionOnLaunch(refreshSession: @Sendable () async throws -> BetterAuthSession) async throws
        -> BetterAuthRestoreResult
    {
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
                                 refreshSession: @Sendable () async throws -> BetterAuthSession) async throws
        -> BetterAuthSession?
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
            let sessionResults = BetterAuthSessionResultHandler(relay: relay,
                                                                materializer: BetterAuthSessionMaterializer(context: context))
            return try await sessionResults.appliedSession(from: .refreshed(session))
        } catch {
            if relay.shouldClearSession(for: error) { try relay.clearSession(event: .sessionExpired) }
            throw error
        }
    }
}

struct BetterAuthSessionAdministrationService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay

    func listSessions(accessToken: String?) async throws -> [BetterAuthSessionListEntry] {
        try await context.network.get(path: context.configuration.endpoints.session.listSessionsPath,
                                      accessToken: accessToken)
    }

    func listDeviceSessions(accessToken: String?) async throws -> [BetterAuthDeviceSession] {
        try await context.network.get(path: context.configuration.endpoints.session.listDeviceSessionsPath,
                                      accessToken: accessToken)
    }

    func setActiveDeviceSession(_ payload: BetterAuthSetActiveDeviceSessionRequest,
                                accessToken: String?) async throws -> BetterAuthSession
    {
        let session: BetterAuthSession = try await context.network
            .post(path: context.configuration.endpoints.session.setActiveDeviceSessionPath,
                  body: payload,
                  accessToken: accessToken)
        let sessionResults = BetterAuthSessionResultHandler(relay: relay,
                                                            materializer: BetterAuthSessionMaterializer(context: context))
        return try await sessionResults.appliedSession(from: .signedIn(session))
    }

    func revokeDeviceSession(_ payload: BetterAuthRevokeDeviceSessionRequest,
                             accessToken: String?,
                             currentAccessToken: String?) async throws -> Bool
    {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.session.revokeDeviceSessionPath,
                  body: payload,
                  accessToken: accessToken)
        if payload.sessionToken == currentAccessToken {
            try relay.clearSession(event: .signedOut)
        }
        return response.status
    }

    func getSessionJWT(accessToken: String?) async throws -> BetterAuthJWT {
        try await context.network.get(path: context.configuration.endpoints.session.sessionJWTPath,
                                      accessToken: accessToken)
    }

    func getJWKS() async throws -> BetterAuthJWKS {
        try await context.network.get(path: context.configuration.endpoints.session.jwksPath,
                                      accessToken: nil)
    }

    func revokeSession(token: String, accessToken: String?, currentAccessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.session.revokeSessionPath,
                  body: RevokeSessionRequest(token: token),
                  accessToken: accessToken)
        if token == currentAccessToken {
            try relay.clearSession(event: .signedOut)
        }
        return response.status
    }

    func revokeSessions(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.session.revokeSessionsPath,
                  accessToken: accessToken)
        try relay.clearSession(event: .signedOut)
        return response.status
    }

    func revokeOtherSessions(accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.session.revokeOtherSessionsPath,
                  accessToken: accessToken)
        return response.status
    }

    func signOut(remotely: Bool, accessToken: String?) async throws {
        if remotely, accessToken != nil {
            _ = try await context.network.post(path: context.configuration.endpoints.session.signOutPath,
                                               accessToken: accessToken) as SignOutResponse
        }
        try relay.clearSession(event: .signedOut)
    }
}

struct BetterAuthPasskeyService {
    let context: BetterAuthSessionContext
    let relay: BetterAuthSessionEventRelay
    let materializer: BetterAuthSessionMaterializer
    private var sessionResults: BetterAuthSessionResultHandler {
        BetterAuthSessionResultHandler(relay: relay, materializer: materializer)
    }

    func passkeyRegistrationOptions(_ request: PasskeyRegistrationOptionsRequest = .init(),
                                    accessToken: String?) async throws -> PasskeyRegistrationOptions
    {
        try await context.network.get(path: context.configuration.endpoints.passkey.registerOptionsPath,
                                      queryItems: [URLQueryItem(name: "name", value: request.name),
                                                   URLQueryItem(name: "authenticatorAttachment",
                                                                value: request.authenticatorAttachment)],
                                      accessToken: accessToken)
    }

    func passkeyAuthenticateOptions(accessToken: String?) async throws -> PasskeyAuthenticationOptions {
        try await context.network.get(path: context.configuration.endpoints.passkey.authenticateOptionsPath,
                                      accessToken: accessToken)
    }

    func registerPasskey(_ payload: PasskeyRegistrationRequest, accessToken: String?) async throws -> Passkey {
        try await context.network.post(path: context.configuration.endpoints.passkey.registerPath,
                                       body: payload,
                                       accessToken: accessToken)
    }

    func authenticateWithPasskey(_ payload: PasskeyAuthenticationRequest) async throws -> BetterAuthSession {
        let response: SocialSignInTransportResponse = try await context.network
            .post(path: context.configuration.endpoints.passkey.authenticatePath,
                  body: payload,
                  accessToken: nil)
        if let session = response.materializedSession {
            return try await sessionResults.appliedSession(from: .signedIn(session))
        }
        if let signedIn = response.signedIn {
            return try await sessionResults.appliedSession(from: .token(token: signedIn.token,
                                                                        fallbackUser: signedIn.user))
        }
        throw BetterAuthError.invalidResponse
    }

    func listPasskeys(accessToken: String?) async throws -> [Passkey] {
        try await context.network.get(path: context.configuration.endpoints.passkey.listPath,
                                      accessToken: accessToken)
    }

    func updatePasskey(_ payload: UpdatePasskeyRequest, accessToken: String?) async throws -> Passkey {
        let response: UpdatePasskeyResponse = try await context.network
            .post(path: context.configuration.endpoints.passkey.updatePath,
                  body: payload,
                  accessToken: accessToken)
        return response.passkey
    }

    func deletePasskey(_ payload: DeletePasskeyRequest, accessToken: String?) async throws -> Bool {
        let response: BetterAuthStatusResponse = try await context.network
            .post(path: context.configuration.endpoints.passkey.deletePath,
                  body: payload,
                  accessToken: accessToken)
        return response.status
    }
}
