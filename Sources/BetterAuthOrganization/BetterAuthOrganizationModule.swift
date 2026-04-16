import BetterAuth
import Foundation

public struct BetterAuthOrganizationModuleRuntime: BetterAuthModuleRuntime {
    public let moduleIdentifier = "organization"
    public let manager: OrganizationManager

    public init(manager: OrganizationManager) {
        self.manager = manager
    }
}

public struct BetterAuthOrganizationModule: BetterAuthModule {
    public let moduleIdentifier = "organization"

    public init() {}

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        BetterAuthOrganizationModuleRuntime(manager: OrganizationManager(client: context))
    }

    public func makeRequestHooks(context _: BetterAuthModuleContext) -> [any BetterAuthRequestHook] {
        []
    }

    public func makeAuthStateListeners(context _: BetterAuthModuleContext) -> [any BetterAuthAuthStateListener] {
        []
    }
}

public extension BetterAuthModuleSupporting {
    var organizationModule: BetterAuthOrganizationModuleRuntime? {
        moduleRuntime(for: "organization", as: BetterAuthOrganizationModuleRuntime.self)
    }
}
