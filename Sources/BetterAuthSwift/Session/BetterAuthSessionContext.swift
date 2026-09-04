import Foundation

/// These are the internal session dependencies. Actor isolation controls most access.
/// A lock protects shared state.
struct BetterAuthSessionContext {
    let configuration: BetterAuthConfiguration
    let state: BetterAuthSessionState
    let sessionService: BetterAuthSessionService
    let refreshService: BetterAuthSessionRefreshService
    let userAccountService: BetterAuthUserAccountService
    let callbackHandler: BetterAuthCallbackHandler
    let network: AuthNetworkClient
    let logger: BetterAuthLogger?
}

struct BetterAuthSessionEventRelay {
    let context: BetterAuthSessionContext

    let commitSession: @Sendable (BetterAuthSession?, AuthChangeEvent) async throws -> AuthStateChange

    func setSession(_ session: BetterAuthSession?, event: AuthChangeEvent) async throws -> AuthStateChange {
        try await commitSession(session, event)
    }

    func clearSession(event: AuthChangeEvent = .signedOut) async throws {
        _ = try await setSession(nil, event: event)
    }

    func shouldClearSession(for error: Error) -> Bool {
        guard let authError = error as? BetterAuthError else { return false }
        if authError.isUnauthorized {
            return true
        }
        if let code = authError.authErrorCode, ErrorParsing.sessionCleanupCodes.contains(code) {
            return true
        }
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
