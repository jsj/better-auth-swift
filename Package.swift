// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "better-auth-swift",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
        .watchOS(.v10),
        .visionOS(.v1),
        .tvOS(.v17)
    ],
    products: [
        .library(name: "BetterAuth", targets: ["BetterAuth"]),
        .library(name: "BetterAuthEmailPassword", targets: ["BetterAuthEmailPassword"]),
        .library(name: "BetterAuthUsername", targets: ["BetterAuthUsername"]),
        .library(name: "BetterAuthAnonymous", targets: ["BetterAuthAnonymous"]),
        .library(name: "BetterAuthSocialOAuth", targets: ["BetterAuthSocialOAuth"]),
        .library(name: "BetterAuthAppleSignIn", targets: ["BetterAuthAppleSignIn"]),
        .library(name: "BetterAuthMagicLink", targets: ["BetterAuthMagicLink"]),
        .library(name: "BetterAuthSwiftUI", targets: ["BetterAuthSwiftUI"]),
        .library(name: "BetterAuthOrganization", targets: ["BetterAuthOrganization"])
    ],
    targets: [
        .target(
            name: "BetterAuth",
            path: "Sources/BetterAuthSwift"
        ),
        .target(
            name: "BetterAuthMagicLink",
            dependencies: ["BetterAuth"]
        ),
        .target(name: "BetterAuthEmailPassword", dependencies: ["BetterAuth"]),
        .target(name: "BetterAuthUsername", dependencies: ["BetterAuth"]),
        .target(name: "BetterAuthAnonymous", dependencies: ["BetterAuth"]),
        .target(name: "BetterAuthSocialOAuth", dependencies: ["BetterAuth"]),
        .target(name: "BetterAuthAppleSignIn", dependencies: ["BetterAuth"]),
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
            dependencies: ["BetterAuth", "BetterAuthSwiftUI", "BetterAuthEmailPassword", "BetterAuthUsername",
                           "BetterAuthAnonymous", "BetterAuthSocialOAuth", "BetterAuthAppleSignIn", "BetterAuthTestHelpers"],
            path: "Tests/BetterAuthSwiftTests"
        ),
        .testTarget(
            name: "BetterAuthMagicLinkTests",
            dependencies: ["BetterAuth", "BetterAuthMagicLink", "BetterAuthTestHelpers"]
        ),
        .testTarget(
            name: "BetterAuthAuthModulesTests",
            dependencies: ["BetterAuth", "BetterAuthEmailPassword", "BetterAuthUsername", "BetterAuthAnonymous",
                           "BetterAuthSocialOAuth", "BetterAuthAppleSignIn", "BetterAuthTestHelpers"]
        ),
        .testTarget(
            name: "BetterAuthOrganizationTests",
            dependencies: ["BetterAuth", "BetterAuthOrganization", "BetterAuthTestHelpers"]
        )
    ],
    swiftLanguageModes: [.v6]
)
