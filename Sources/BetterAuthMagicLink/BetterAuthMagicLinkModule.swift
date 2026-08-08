import BetterAuth
import Foundation

public struct BetterAuthMagicLinkModuleRuntime: BetterAuthModuleRuntime, BetterAuthFeatureClient {
    public let moduleIdentifier = BetterAuthMagicLinkModule.identifier
    public let magicLinks: BetterAuthMagicLinkClient

    public init(magicLinks: BetterAuthMagicLinkClient) {
        self.magicLinks = magicLinks
    }
}

public struct BetterAuthMagicLinkModule: BetterAuthModule {
    public static let identifier = "magic-link"
    public let moduleIdentifier = Self.identifier
    private let endpoints: BetterAuthMagicLinkEndpoints

    public init(endpoints: BetterAuthMagicLinkEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        BetterAuthMagicLinkModuleRuntime(magicLinks: BetterAuthMagicLinkClient(context: context,
                                                                               endpoints: endpoints))
    }
}

public enum BetterAuthMagicLinkModuleError: LocalizedError, Sendable, Equatable {
    case notRegistered

    public var errorDescription: String? {
        "Register BetterAuthMagicLinkModule() when you create BetterAuthClient."
    }
}

public extension BetterAuthModuleSupporting {
    var magicLinkModule: BetterAuthMagicLinkModuleRuntime? {
        moduleRuntime(for: BetterAuthMagicLinkModule.identifier, as: BetterAuthMagicLinkModuleRuntime.self)
    }

    func requireMagicLinks() throws -> BetterAuthMagicLinkClient {
        guard let magicLinks = magicLinkModule?.magicLinks else {
            throw BetterAuthMagicLinkModuleError.notRegistered
        }
        return magicLinks
    }
}
