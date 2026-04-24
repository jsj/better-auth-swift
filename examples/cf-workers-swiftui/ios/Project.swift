import ProjectDescription
import ProjectDescriptionHelpers

private let targetBaseSettings: SettingsDictionary = {
    var settings: SettingsDictionary = ["CODE_SIGN_STYLE": .string(ExampleEnvironmentDefaults.codeSignStyle)]

    if let developmentTeam = ExampleEnvironmentDefaults.developmentTeam {
        settings["DEVELOPMENT_TEAM"] = .string(developmentTeam)
    }

    return settings
}()

let project = Project(name: "BetterAuthExample",
                      options: .options(defaultKnownRegions: ["en"],
                                        developmentRegion: "en"),
                      packages: [.package(path: "../../..")],
                      settings: .settings(base: ["SWIFT_VERSION": "6.0"]),
                      targets: [.target(name: "BetterAuthExample",
                                        destinations: .iOS,
                                        product: .app,
                                        bundleId: "sh.jsj.better-auth-swift-swiftui-example.apple",
                                        deploymentTargets: .iOS("17.0"),
                                        infoPlist: .extendingDefault(with: ["CFBundleDisplayName": "BetterAuthExample",
                                                                            "CFBundleURLTypes": [["CFBundleURLName": "betterauth",
                                                                                                  "CFBundleURLSchemes": ["betterauth"]]],
                                                                            "API_BASE_URL": .string(ExampleEnvironmentDefaults
                                                                                .apiBaseURL),
                                                                            "UILaunchScreen": [:]]),
                                        sources: ["App/Sources/**"],
                                        resources: ["App/Resources/**"],
                                        entitlements: .dictionary(["com.apple.developer.applesignin": ["Default"]]),
                                        dependencies: [.package(product: "BetterAuth")],
                                        settings: .settings(base: targetBaseSettings)),
                                .target(name: "BetterAuthExampleTests",
                                        destinations: .iOS,
                                        product: .unitTests,
                                        bundleId: "sh.jsj.better-auth-swift-swiftui-example.apple.tests",
                                        deploymentTargets: .iOS("17.0"),
                                        infoPlist: .default,
                                        sources: ["App/Tests/**"],
                                        dependencies: [.target(name: "BetterAuthExample"),
                                                       .package(product: "BetterAuth")])])
