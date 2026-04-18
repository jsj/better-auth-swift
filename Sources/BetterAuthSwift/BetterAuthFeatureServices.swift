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
