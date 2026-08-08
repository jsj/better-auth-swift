import BetterAuth
import Foundation

public extension AuthStore {
    // MARK: - Session

    func restore() async {
        await bootstrap()
    }

    func bootstrap() async {
        let identifier = beginOperation()
        launchState = .restoring
        defer { endOperation(identifier) }
        do {
            try Task.checkCancellation()
            let result = try await sessionAuth.restoreSessionOnLaunch()
            lastRestoreResult = result
            applyRestoreResult(result)
            recordSuccess(for: identifier)
        } catch is CancellationError {
            return
        } catch {
            lastRestoreResult = nil
            session = nil
            launchState = .failed
            recordFailure(error, for: identifier)
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
