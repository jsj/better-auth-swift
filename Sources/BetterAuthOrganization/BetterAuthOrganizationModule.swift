import BetterAuth
import Foundation

public struct BetterAuthOrganizationModuleRuntime: BetterAuthModuleRuntime, BetterAuthFeatureClient {
    public let moduleIdentifier = "organization"
    public let manager: OrganizationManager

    public init(manager: OrganizationManager) {
        self.manager = manager
    }
}

public struct BetterAuthOrganizationModule: BetterAuthModule {
    public let moduleIdentifier = "organization"
    private let endpoints: BetterAuthOrganizationEndpoints

    public init(endpoints: BetterAuthOrganizationEndpoints = .init()) {
        self.endpoints = endpoints
    }

    public func configure(context: BetterAuthModuleContext) -> BetterAuthModuleRuntime {
        BetterAuthOrganizationModuleRuntime(manager: OrganizationManager(client: context, endpoints: endpoints))
    }
}

public extension BetterAuthModuleSupporting {
    var organizationModule: BetterAuthOrganizationModuleRuntime? {
        moduleRuntime(for: "organization", as: BetterAuthOrganizationModuleRuntime.self)
    }

    var organizationFeatureClient: BetterAuthOrganizationModuleRuntime? {
        featureClient(for: "organization", as: BetterAuthOrganizationModuleRuntime.self)
    }
}
