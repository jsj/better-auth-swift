import BetterAuth
import Foundation
import Observation

/// Observable SwiftUI state wrapper around ``BetterAuthClient``.
///
/// Provides `session`, `isLoading`, and `statusMessage` for driving UI,
/// plus async methods that mirror every auth flow on the session manager.
@Observable
@MainActor
public final class AuthStore {
    /// The current authenticated session, or `nil` if signed out.
    public internal(set) var session: BetterAuthSession?
    /// Explicit app-launch state for bootstrapping root UI.
    public internal(set) var launchState: AuthLaunchState = .idle
    /// The last detailed restore outcome returned by the core SDK.
    public internal(set) var lastRestoreResult: BetterAuthRestoreResult?
    /// `true` while any auth operation is in flight.
    public internal(set) var isLoading = false
    /// Human-readable status or error message from the last operation.
    public internal(set) var statusMessage: String?
    /// Structured error captured from the last failed operation.
    public internal(set) var lastError: BetterAuthError?

    let auth: any BetterAuthAuthPerforming
    private var authStateTask: Task<Void, Never>?

    public init(client: some BetterAuthClientProtocol) {
        auth = client.authLifecycle
        startAuthStateObservation()
    }

    // MARK: - Helpers

    private func startAuthStateObservation() {
        authStateTask?.cancel()
        let auth = auth
        authStateTask = Task { [weak self, auth] in
            for await change in auth.authStateChanges {
                guard !Task.isCancelled else { return }
                guard let self else { return }
                self.applyAuthStateChange(change)
            }
        }
    }

    private func stopAuthStateObservation() {
        authStateTask?.cancel()
        authStateTask = nil
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
                statusMessage = "Session restored; refresh deferred"

            @unknown default:
                launchState = .authenticated(restoredSession)
                statusMessage = "Session restored"
            }

        case .cleared:
            session = nil
            launchState = .unauthenticated
            statusMessage = "Stored session cleared"

        @unknown default:
            session = nil
            launchState = .unauthenticated
            statusMessage = "Session state updated"
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

        @unknown default:
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
        } catch {
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
        }
    }

    func performThrowing<T>(_ operation: () async throws -> T) async throws -> T {
        isLoading = true
        defer { isLoading = false }
        do {
            try Task.checkCancellation()
            let result = try await operation()
            lastError = nil
            return result
        } catch {
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
            throw error
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
