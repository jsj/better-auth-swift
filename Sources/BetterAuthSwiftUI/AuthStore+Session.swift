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
            let result = try await auth.restoreSessionOnLaunch()
            lastError = nil
            lastRestoreResult = result
            applyRestoreResult(result)
        } catch {
            lastRestoreResult = nil
            session = nil
            launchState = .failed
            lastError = normalizeError(error)
            statusMessage = error.localizedDescription
        }
    }

    func refresh() async {
        await perform {
            _ = try await auth.refreshSession()
            statusMessage = "Session refreshed"
        }
    }

    func fetchCurrentSession() async {
        await perform {
            _ = try await auth.fetchCurrentSession()
            statusMessage = "Session fetched"
        }
    }

    func signOut(remotely: Bool = true) async {
        await perform {
            try await auth.signOut(remotely: remotely)
            statusMessage = "Signed out"
        }
    }
}
