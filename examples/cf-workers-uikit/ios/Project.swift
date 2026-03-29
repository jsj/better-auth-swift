import ProjectDescription
import ProjectDescriptionHelpers

private let targetBaseSettings: SettingsDictionary = {
    var settings: SettingsDictionary = [
        "CODE_SIGN_STYLE": .string(ExampleEnvironmentDefaults.codeSignStyle)
    ]

    if let developmentTeam = ExampleEnvironmentDefaults.developmentTeam {
        settings["DEVELOPMENT_TEAM"] = .string(developmentTeam)
    }

    return settings
}()

let project = Project(
    name: "BetterAuthUIKitExample",
    options: .options(
        defaultKnownRegions: ["en"],
        developmentRegion: "en"
    ),
    packages: [
        .package(path: "../../..")
    ],
    settings: .settings(
        base: [
            "SWIFT_VERSION": "6.0"
        ]
    ),
    targets: [
        .target(
            name: "BetterAuthUIKitExample",
            destinations: .iOS,
            product: .app,
            bundleId: "sh.jsj.better-auth-swift-uikit-example.apple",
            deploymentTargets: .iOS("18.0"),
            infoPlist: .extendingDefault(with: [
                "CFBundleDisplayName": "BetterAuthUIKitExample",
                "API_BASE_URL": .string(ExampleEnvironmentDefaults.apiBaseURL),
                "UILaunchScreen": [:]
            ]),
            sources: [
                "App/Sources/**"
            ],
            resources: ["App/Resources/**"],
            entitlements: .dictionary([
                "com.apple.developer.applesignin": ["Default"]
            ]),
            dependencies: [
                .package(product: "BetterAuth")
            ],
            settings: .settings(base: targetBaseSettings),
            additionalFiles: [
                "App/Sources/Auth/Views/**"
            ]
        ),
        .target(
            name: "BetterAuthUIKitExampleTests",
            destinations: .iOS,
            product: .unitTests,
            bundleId: "sh.jsj.better-auth-swift-uikit-example.apple.tests",
            deploymentTargets: .iOS("18.0"),
            infoPlist: .default,
            sources: ["App/Tests/**"],
            dependencies: [
                .target(name: "BetterAuthUIKitExample"),
                .package(product: "BetterAuth")
            ]
        )
    ]
)
