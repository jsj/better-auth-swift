// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "better-auth-swift",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(name: "BetterAuth", targets: ["BetterAuth"]),
        .library(name: "BetterAuthSwiftUI", targets: ["BetterAuthSwiftUI"]),
        .library(name: "BetterAuthOrganization", targets: ["BetterAuthOrganization"])
    ],
    targets: [
        .target(
            name: "BetterAuth",
            path: "Sources/BetterAuthSwift"
        ),
        .target(
            name: "BetterAuthSwiftUI",
            dependencies: ["BetterAuth"]
        ),
        .target(
            name: "BetterAuthOrganization",
            dependencies: ["BetterAuth"]
        ),
        .target(
            name: "BetterAuthTestHelpers",
            dependencies: ["BetterAuth"],
            path: "Tests/BetterAuthTestHelpers"
        ),
        .testTarget(
            name: "BetterAuthSwiftTests",
            dependencies: ["BetterAuth", "BetterAuthSwiftUI", "BetterAuthTestHelpers"],
            path: "Tests/BetterAuthSwiftTests"
        ),
        .testTarget(
            name: "BetterAuthOrganizationTests",
            dependencies: ["BetterAuth", "BetterAuthOrganization", "BetterAuthTestHelpers"]
        )
    ],
    swiftLanguageModes: [.v6]
)
