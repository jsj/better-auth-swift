import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Session

    func restore() async {
        await bootstrap()
    }

    func bootstrap() async {
        isLoading = true
        launchState = .restoring
        defer { isLoading = false }
        do {
            let result = try await sessionAuth.restoreSessionOnLaunch()
            lastError = nil
            lastUnderlyingError = nil
            lastRestoreResult = result
            applyRestoreResult(result)
        } catch {
            lastRestoreResult = nil
            session = nil
            launchState = .failed
            lastError = normalizeError(error)
            lastUnderlyingError = error
            statusMessage = error.localizedDescription
        }
    }

    func refresh() async {
        await perform {
            _ = try await sessionAuth.refreshSession()
            statusMessage = "Session refreshed"
        }
    }

    func fetchCurrentSession() async {
        await perform {
            _ = try await sessionAuth.fetchCurrentSession()
            statusMessage = "Session fetched"
        }
    }

    func signOut(remotely: Bool = true) async {
        await perform {
            try await sessionAuth.signOut(remotely: remotely)
            statusMessage = "Signed out"
        }
    }
}
