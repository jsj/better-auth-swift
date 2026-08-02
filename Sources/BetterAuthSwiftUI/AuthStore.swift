import BetterAuth
import Foundation
import Observation

/// Observable SwiftUI state wrapper around ``BetterAuthClient``.
///
/// Provides `session`, `isLoading`, and `statusMessage` for the UI.
/// Its asynchronous methods mirror each authentication flow on the session manager.
@Observable
@MainActor
public final class AuthStore {
    /// The current authenticated session, or `nil` if signed out.
    public internal(set) var session: BetterAuthSession?
    /// The explicit state of the root UI during app launch.
    public internal(set) var launchState: AuthLaunchState = .idle
    /// The last detailed restore outcome returned by the core SDK.
    public internal(set) var lastRestoreResult: BetterAuthRestoreResult?
    /// `true` while any auth operation is in flight.
    public internal(set) var isLoading = false
    /// Human-readable status or error message from the last operation.
    public internal(set) var statusMessage: String?
    /// Structured error captured from the last failed operation.
    public internal(set) var lastError: BetterAuthError?
    /// The original error captured from the last failed operation.
    public internal(set) var lastUnderlyingError: (any Error)?

    let sessionAuth: any BetterAuthSessionLifecycle & BetterAuthSessionFetching
    let primaryAuth: any BetterAuthPrimaryAuthPerforming
    let oauthAuth: any BetterAuthOAuthPerforming
    let oneTimeCodeAuth: any BetterAuthOneTimeCodePerforming
    let twoFactorAuth: any BetterAuthTwoFactorPerforming
    let passkeyAuth: any BetterAuthPasskeyPerforming
    let accountAuth: any BetterAuthAccountPerforming
    let sessionAdministration: any BetterAuthSessionAdministrating
    private let authStateObservation = AuthStateObservation()

    public init(client: some BetterAuthClientProtocol) {
        sessionAuth = client.authSessionLifecycle
        primaryAuth = client.primaryAuth
        oauthAuth = client.oauthAuth
        oneTimeCodeAuth = client.oneTimeCodeAuth
        twoFactorAuth = client.twoFactorAuth
        passkeyAuth = client.passkeyAuth
        accountAuth = client.accountAuth
        sessionAdministration = client.sessionAdministration
        startAuthStateObservation()
    }

    // MARK: - Helpers

    private func startAuthStateObservation() {
        authStateObservation.cancel()
        let sessionAuth = sessionAuth
        authStateObservation.task = Task { [weak self, sessionAuth] in
            for await change in sessionAuth.authStateChanges {
                guard !Task.isCancelled else { return }
                guard let self else { return }
                self.applyAuthStateChange(change)
            }
        }
    }

    private func stopAuthStateObservation() {
        authStateObservation.cancel()
    }

    func applyRestoreResult(_ result: BetterAuthRestoreResult) {
        switch result {
        case .noStoredSession:
            session = nil
            launchState = .unauthenticated
            statusMessage = "No stored session"

        case let .restored(restoredSession, _, refresh):
            session = restoredSession
            switch refresh {
            case .notNeeded:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored"

            case .refreshed:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored and refreshed"

            case .deferred:
                launchState = .recoverableFailure(restoredSession)
                statusMessage = "Session restored. Refresh deferred."
            }

        case .cleared:
            session = nil
            launchState = .unauthenticated
            statusMessage = "Stored session cleared"
        }
    }

    func applyAuthStateChange(_ change: AuthStateChange) {
        session = change.session
        switch change.transition?.phase {
        case .authenticated:
            if let session = change.session {
                launchState = .authenticated(session)
            }

        case .unauthenticated:
            launchState = .unauthenticated

        case .refreshing:
            if let session = change.session {
                launchState = .authenticated(session)
            }

        case .restoring:
            launchState = .restoring

        case .failed:
            launchState = .failed

        case .idle, nil:
            if let session = change.session {
                launchState = .authenticated(session)
            } else if change.event == .signedOut || change.event == .sessionExpired {
                launchState = .unauthenticated
            }
        }
    }

    func perform(_ operation: () async throws -> Void) async {
        isLoading = true
        defer { isLoading = false }
        do {
            try Task.checkCancellation()
            try await operation()
            lastError = nil
            lastUnderlyingError = nil
        } catch {
            lastError = normalizeError(error)
            lastUnderlyingError = error
            statusMessage = error.localizedDescription
        }
    }

    func perform(status successStatus: String, _ operation: () async throws -> Void) async {
        await perform {
            try await operation()
            statusMessage = successStatus
        }
    }

    func performThrowing<T: Sendable>(_ operation: () async throws -> T) async throws -> T {
        isLoading = true
        defer { isLoading = false }
        do {
            try Task.checkCancellation()
            let result = try await operation()
            lastError = nil
            lastUnderlyingError = nil
            return result
        } catch {
            lastError = normalizeError(error)
            lastUnderlyingError = error
            statusMessage = error.localizedDescription
            throw error
        }
    }

    func performThrowing<T: Sendable>(status successStatus: String,
                                      _ operation: () async throws -> T) async throws -> T
    {
        try await performThrowing {
            let result = try await operation()
            statusMessage = successStatus
            return result
        }
    }

    func performThrowing<T: Sendable>(status successStatus: (T) -> String,
                                      _ operation: () async throws -> T) async throws -> T
    {
        try await performThrowing {
            let result = try await operation()
            statusMessage = successStatus(result)
            return result
        }
    }

    func normalizeError(_ error: Error) -> BetterAuthError? {
        if let betterAuthError = error as? BetterAuthError {
            return betterAuthError
        }
        return nil
    }

    public func shutdown() {
        stopAuthStateObservation()
    }
}

private final class AuthStateObservation {
    var task: Task<Void, Never>?

    func cancel() {
        task?.cancel()
        task = nil
    }

    deinit {
        task?.cancel()
    }
}
