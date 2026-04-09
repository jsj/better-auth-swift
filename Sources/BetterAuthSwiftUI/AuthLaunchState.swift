import BetterAuth
import Foundation

public enum AuthLaunchState: Sendable, Equatable {
    case idle
    case restoring
    case authenticated(BetterAuthSession)
    case unauthenticated
    case recoverableFailure(BetterAuthSession?)
    case failed
}
