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
        .library(name: "BetterAuthSwiftUI", targets: ["BetterAuthSwiftUI"])
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
        .testTarget(
            name: "BetterAuthSwiftTests",
            dependencies: ["BetterAuth", "BetterAuthSwiftUI"],
            path: "Tests/BetterAuthSwiftTests"
        )
    ],
    swiftLanguageModes: [.v6]
)
