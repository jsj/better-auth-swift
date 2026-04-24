import Foundation

@frozen public enum BetterAuthSessionPhase: Sendable, Equatable {
    case idle
    case restoring
    case authenticated
    case unauthenticated
    case refreshing
    case failed
}

@frozen public enum BetterAuthRestoreSource: Sendable, Equatable {
    case memory
    case keychain
}

@frozen public enum BetterAuthRefreshDisposition: Sendable, Equatable {
    case notNeeded
    case refreshed
    case deferred
}

@frozen public enum BetterAuthRestoreClearReason: Sendable, Equatable {
    case invalidSession
    case sessionExpired
    case refreshTokenExpired
    case invalidRefreshToken
    case unauthorized
    case storageFailure
}

@frozen public enum BetterAuthRestoreResult: Sendable, Equatable {
    case noStoredSession
    case restored(BetterAuthSession,
                  source: BetterAuthRestoreSource,
                  refresh: BetterAuthRefreshDisposition)
    case cleared(BetterAuthRestoreClearReason)
}

@frozen public enum BetterAuthIncomingURL: Sendable, Equatable {
    case genericOAuth(GenericOAuthCallbackRequest)
    case magicLink(MagicLinkVerifyRequest)
    case verifyEmail(VerifyEmailRequest)
    case unsupported
}

@frozen public enum BetterAuthHandledURLResult: Sendable, Equatable {
    case genericOAuth(BetterAuthSession)
    case magicLink(MagicLinkVerificationResult)
    case verifyEmail(VerifyEmailResult)
    case ignored
}

public struct BetterAuthSessionTransition: Sendable, Equatable {
    public let phase: BetterAuthSessionPhase
    public let source: BetterAuthRestoreSource?
    public let refreshDisposition: BetterAuthRefreshDisposition?
    public let clearReason: BetterAuthRestoreClearReason?

    public init(phase: BetterAuthSessionPhase,
                source: BetterAuthRestoreSource? = nil,
                refreshDisposition: BetterAuthRefreshDisposition? = nil,
                clearReason: BetterAuthRestoreClearReason? = nil)
    {
        self.phase = phase
        self.source = source
        self.refreshDisposition = refreshDisposition
        self.clearReason = clearReason
    }
}
