import Foundation

struct BetterAuthSessionContext: Sendable {
    let configuration: BetterAuthConfiguration
    let state: BetterAuthSessionState
    let sessionService: BetterAuthSessionService
    let refreshService: BetterAuthSessionRefreshService
    let authFlowService: BetterAuthAuthFlowService
    let userAccountService: BetterAuthUserAccountService
    let callbackHandler: BetterAuthCallbackHandler
    let network: AuthNetworkClient
    let logger: BetterAuthLogger?
}

struct BetterAuthSessionEventRelay: Sendable {
    let context: BetterAuthSessionContext
    let refreshSession: @Sendable () async throws -> BetterAuthSession

    func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent) throws -> AuthStateChange {
        let previousSession = context.state.replaceCurrentSession(session)
        do {
            try context.sessionService.persist(session)
        } catch {
            _ = context.state.replaceCurrentSession(previousSession)
            throw error
        }
        let change = AuthStateChange(event: event,
                                     session: session,
                                     transition: transition(for: event, session: session))
        context.state.eventEmitter.yield(change)
        return change
    }

    func clearSession(event: AuthChangeEvent = .signedOut) throws {
        _ = try setSession(nil, event: event)
    }

    func shouldClearSession(for error: Error) -> Bool {
        guard let authError = error as? BetterAuthError else { return false }
        if authError.isUnauthorized { return true }
        if let code = authError.authErrorCode, ErrorParsing.sessionCleanupCodes.contains(code) { return true }
        return false
    }

    func clearReason(for error: Error) -> BetterAuthRestoreClearReason {
        guard let authError = error as? BetterAuthError else { return .unauthorized }
        switch authError.authErrorCode {
        case .sessionExpired:
            return .sessionExpired

        case .sessionNotFound:
            return .invalidSession

        case .refreshTokenExpired:
            return .refreshTokenExpired

        case .invalidRefreshToken:
            return .invalidRefreshToken

        default:
            return authError.isUnauthorized ? .unauthorized : .storageFailure
        }
    }

    func validSession() async throws -> BetterAuthSession {
        if let current = context.state.currentSession, current.needsRefresh(clockSkew: context.configuration.auth.clockSkew) {
            return try await refreshSession()
        }
        if let current = context.state.currentSession { return current }
        throw BetterAuthError.missingSession
    }
}

extension BetterAuthSessionEventRelay {
    func transition(for event: AuthChangeEvent,
                    session: BetterAuthSession?) -> BetterAuthSessionTransition
    {
        switch event {
        case .initialSession:
            BetterAuthSessionTransition(phase: session == nil ? .unauthenticated : .authenticated)

        case .signedIn, .userUpdated:
            BetterAuthSessionTransition(phase: .authenticated)

        case .signedOut, .sessionExpired:
            BetterAuthSessionTransition(phase: .unauthenticated)

        case .tokenRefreshed:
            BetterAuthSessionTransition(phase: .refreshing)
        }
    }
}
