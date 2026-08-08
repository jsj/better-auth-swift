import ProjectDescription

let baseSettings: SettingsDictionary = ["SWIFT_VERSION": "6.0",
                                        "ENABLE_MODULE_VERIFIER": "NO",
                                        "BUILD_LIBRARY_FOR_DISTRIBUTION": "YES",
                                        "SUPPORTS_MACCATALYST": "NO",
                                        "CODE_SIGNING_ALLOWED": "NO",
                                        "CODE_SIGNING_REQUIRED": "NO"]

let frameworkRunpaths: [String] = ["$(inherited)",
                                   "@executable_path/Frameworks",
                                   "@loader_path/Frameworks"]

let testRunpaths: [String] = ["$(inherited)",
                              "@loader_path/../Frameworks",
                              "@executable_path/../Frameworks"]

func authModuleTarget(_ name: String) -> Target {
    .target(name: name,
            destinations: [.iPhone, .iPad, .mac, .appleWatch, .appleVision, .appleTv],
            product: .framework,
            bundleId: "com.jsj.betterauthswift.\(name)",
            deploymentTargets: .multiplatform(iOS: "17.0",
                                              macOS: "14.0",
                                              watchOS: "10.0",
                                              tvOS: "17.0",
                                              visionOS: "1.0"),
            infoPlist: .default,
            sources: ["Sources/\(name)/**"],
            dependencies: [.target(name: "BetterAuth")],
            settings: .settings(base: ["DEFINES_MODULE": "YES",
                                       "SKIP_INSTALL": "NO",
                                       "LD_RUNPATH_SEARCH_PATHS": .array(frameworkRunpaths)]))
}

func authModuleScheme(_ name: String) -> Scheme {
    .scheme(name: name,
            shared: true,
            buildAction: .buildAction(targets: [TargetReference(stringLiteral: name)]),
            runAction: .runAction(configuration: "Debug"),
            archiveAction: .archiveAction(configuration: "Release"))
}

let lintScript = """
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
SWIFTLINT_PATH="$(command -v swiftlint 2>/dev/null || xcrun --find swiftlint 2>/dev/null)"
FILE_LIST_PATH="$DERIVED_FILE_DIR/BetterAuth-swiftlint.xcfilelist"
mkdir -p "$DERIVED_FILE_DIR"
if [ -d "$SRCROOT/Sources" ]; then
  find "$SRCROOT/Sources" -type f -name "*.swift" | sort > "$FILE_LIST_PATH"
else
  : > "$FILE_LIST_PATH"
fi
if [ -n "$SWIFTLINT_PATH" ]; then
  if [ -s "$FILE_LIST_PATH" ]; then
    index=0
    while IFS= read -r file; do
      if [ -n "$file" ]; then
        var="SCRIPT_INPUT_FILE_${index}"
        export "$var=$file"
        index=$((index + 1))
      fi
    done < "$FILE_LIST_PATH"
    export SCRIPT_INPUT_FILE_COUNT=$index
    "$SWIFTLINT_PATH" --config "$SRCROOT/.swiftlint.yml" --strict --use-script-input-files
  else
    "$SWIFTLINT_PATH" --config "$SRCROOT/.swiftlint.yml" --strict
  fi
else
  echo "SwiftLint not found, skipping linting"
fi
"""

let formatScript = """
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
SWIFTFORMAT_PATH="$(command -v swiftformat 2>/dev/null || xcrun --find swiftformat 2>/dev/null)"
if [ -n "$SWIFTFORMAT_PATH" ]; then
  cd "$SRCROOT"
  "$SWIFTFORMAT_PATH" . --config .swiftformat || exit 1
  "$SWIFTFORMAT_PATH" . --lint --config .swiftformat
else
  echo "SwiftFormat not found, skipping formatting check"
fi
"""

let project = Project(name: "better-auth-swift",
                      organizationName: "com.jsj.betterauthswift",
                      options: .options(automaticSchemesOptions: .disabled,
                                        defaultKnownRegions: ["en"],
                                        disableBundleAccessors: true,
                                        disableSynthesizedResourceAccessors: true),
                      settings: .settings(base: baseSettings,
                                          configurations: [.debug(name: "Debug"),
                                                           .release(name: "Release")],
                                          defaultSettings: .recommended),
                      targets: [.target(name: "BetterAuth",
                                        destinations: [.iPhone, .iPad, .mac, .appleWatch, .appleVision, .appleTv],
                                        product: .framework,
                                        bundleId: "com.jsj.betterauthswift.BetterAuth",
                                        deploymentTargets: .multiplatform(iOS: "17.0",
                                                                          macOS: "14.0",
                                                                          watchOS: "10.0",
                                                                          tvOS: "17.0",
                                                                          visionOS: "1.0"),
                                        infoPlist: .default,
                                        sources: ["Sources/BetterAuthSwift/**",
                                                  "Sources/BetterAuthSwift/**/*.swift"],
                                        scripts: [.pre(script: lintScript,
                                                       name: "SwiftLint",
                                                       outputPaths: ["$(DERIVED_FILE_DIR)/swiftlint.log"]),
                                                  .pre(script: formatScript,
                                                       name: "SwiftFormat",
                                                       outputPaths: ["$(DERIVED_FILE_DIR)/swiftformat.log"])],
                                        settings: .settings(base: ["DEFINES_MODULE": "YES",
                                                                   "SKIP_INSTALL": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(frameworkRunpaths)])),
                                .target(name: "BetterAuthMagicLink",
                                        destinations: [.iPhone, .iPad, .mac, .appleWatch, .appleVision, .appleTv],
                                        product: .framework,
                                        bundleId: "com.jsj.betterauthswift.BetterAuthMagicLink",
                                        deploymentTargets: .multiplatform(iOS: "17.0",
                                                                          macOS: "14.0",
                                                                          watchOS: "10.0",
                                                                          tvOS: "17.0",
                                                                          visionOS: "1.0"),
                                        infoPlist: .default,
                                        sources: ["Sources/BetterAuthMagicLink/**"],
                                        dependencies: [.target(name: "BetterAuth")],
                                        settings: .settings(base: ["DEFINES_MODULE": "YES",
                                                                   "SKIP_INSTALL": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(frameworkRunpaths)])),
                                authModuleTarget("BetterAuthEmailPassword"),
                                authModuleTarget("BetterAuthUsername"),
                                authModuleTarget("BetterAuthAnonymous"),
                                authModuleTarget("BetterAuthSocialOAuth"),
                                authModuleTarget("BetterAuthAppleSignIn"),
                                .target(name: "BetterAuthSwiftUI",
                                        destinations: [.iPhone, .iPad, .mac, .appleWatch, .appleVision, .appleTv],
                                        product: .framework,
                                        bundleId: "com.jsj.betterauthswift.BetterAuthSwiftUI",
                                        deploymentTargets: .multiplatform(iOS: "17.0",
                                                                          macOS: "14.0",
                                                                          watchOS: "10.0",
                                                                          tvOS: "17.0",
                                                                          visionOS: "1.0"),
                                        infoPlist: .default,
                                        sources: ["Sources/BetterAuthSwiftUI/**"],
                                        dependencies: [.target(name: "BetterAuth")],
                                        settings: .settings(base: ["DEFINES_MODULE": "YES",
                                                                   "SKIP_INSTALL": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(frameworkRunpaths)])),
                                .target(name: "BetterAuthOrganization",
                                        destinations: [.iPhone, .iPad, .mac, .appleWatch, .appleVision, .appleTv],
                                        product: .framework,
                                        bundleId: "com.jsj.betterauthswift.BetterAuthOrganization",
                                        deploymentTargets: .multiplatform(iOS: "17.0",
                                                                          macOS: "14.0",
                                                                          watchOS: "10.0",
                                                                          tvOS: "17.0",
                                                                          visionOS: "1.0"),
                                        infoPlist: .default,
                                        sources: ["Sources/BetterAuthOrganization/**"],
                                        dependencies: [.target(name: "BetterAuth")],
                                        settings: .settings(base: ["DEFINES_MODULE": "YES",
                                                                   "SKIP_INSTALL": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(frameworkRunpaths)])),
                                .target(name: "BetterAuthTestHelpers",
                                        destinations: [.mac],
                                        product: .framework,
                                        bundleId: "com.jsj.betterauthswift.testhelpers",
                                        deploymentTargets: .macOS("14.0"),
                                        infoPlist: .default,
                                        sources: ["Tests/BetterAuthTestHelpers/**"],
                                        dependencies: [.target(name: "BetterAuth")],
                                        settings: .settings(base: ["DEFINES_MODULE": "YES",
                                                                   "SKIP_INSTALL": "YES",
                                                                   "BUILD_LIBRARY_FOR_DISTRIBUTION": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(testRunpaths)])),
                                .target(name: "BetterAuthSwiftTests",
                                        destinations: [.mac],
                                        product: .unitTests,
                                        bundleId: "com.jsj.betterauthswift.tests",
                                        deploymentTargets: .macOS("14.0"),
                                        infoPlist: .default,
                                        sources: ["Tests/BetterAuthSwiftTests/**"],
                                        dependencies: [.target(name: "BetterAuth"),
                                                       .target(name: "BetterAuthSwiftUI"),
                                                       .target(name: "BetterAuthEmailPassword"),
                                                       .target(name: "BetterAuthUsername"),
                                                       .target(name: "BetterAuthAnonymous"),
                                                       .target(name: "BetterAuthSocialOAuth"),
                                                       .target(name: "BetterAuthAppleSignIn"),
                                                       .target(name: "BetterAuthTestHelpers")],
                                        settings: .settings(base: ["BUNDLE_LOADER": "",
                                                                   "TEST_HOST": "",
                                                                   "BUILD_LIBRARY_FOR_DISTRIBUTION": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(testRunpaths)])),
                                .target(name: "BetterAuthOrganizationTests",
                                        destinations: [.mac],
                                        product: .unitTests,
                                        bundleId: "com.jsj.betterauthswift.organization-tests",
                                        deploymentTargets: .macOS("14.0"),
                                        infoPlist: .default,
                                        sources: ["Tests/BetterAuthOrganizationTests/**"],
                                        dependencies: [.target(name: "BetterAuth"),
                                                       .target(name: "BetterAuthOrganization"),
                                                       .target(name: "BetterAuthTestHelpers")],
                                        settings: .settings(base: ["BUNDLE_LOADER": "",
                                                                   "TEST_HOST": "",
                                                                   "BUILD_LIBRARY_FOR_DISTRIBUTION": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(testRunpaths)])),
                                .target(name: "BetterAuthMagicLinkTests",
                                        destinations: [.mac],
                                        product: .unitTests,
                                        bundleId: "com.jsj.betterauthswift.magic-link-tests",
                                        deploymentTargets: .macOS("14.0"),
                                        infoPlist: .default,
                                        sources: ["Tests/BetterAuthMagicLinkTests/**"],
                                        dependencies: [.target(name: "BetterAuth"),
                                                       .target(name: "BetterAuthMagicLink"),
                                                       .target(name: "BetterAuthTestHelpers")],
                                        settings: .settings(base: ["BUNDLE_LOADER": "",
                                                                   "TEST_HOST": "",
                                                                   "BUILD_LIBRARY_FOR_DISTRIBUTION": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(testRunpaths)])),
                                .target(name: "BetterAuthAuthModulesTests",
                                        destinations: [.mac],
                                        product: .unitTests,
                                        bundleId: "com.jsj.betterauthswift.auth-modules-tests",
                                        deploymentTargets: .macOS("14.0"),
                                        infoPlist: .default,
                                        sources: ["Tests/BetterAuthAuthModulesTests/**"],
                                        dependencies: [.target(name: "BetterAuth"),
                                                       .target(name: "BetterAuthEmailPassword"),
                                                       .target(name: "BetterAuthUsername"),
                                                       .target(name: "BetterAuthAnonymous"),
                                                       .target(name: "BetterAuthSocialOAuth"),
                                                       .target(name: "BetterAuthAppleSignIn")],
                                        settings: .settings(base: ["BUNDLE_LOADER": "",
                                                                   "TEST_HOST": "",
                                                                   "BUILD_LIBRARY_FOR_DISTRIBUTION": "NO",
                                                                   "LD_RUNPATH_SEARCH_PATHS": .array(testRunpaths)]))],
                      schemes: [.scheme(name: "BetterAuth",
                                        shared: true,
                                        buildAction: .buildAction(targets: ["BetterAuth"]),
                                        runAction: .runAction(configuration: "Debug"),
                                        archiveAction: .archiveAction(configuration: "Release")),
                                authModuleScheme("BetterAuthEmailPassword"),
                                authModuleScheme("BetterAuthUsername"),
                                authModuleScheme("BetterAuthAnonymous"),
                                authModuleScheme("BetterAuthSocialOAuth"),
                                authModuleScheme("BetterAuthAppleSignIn"),
                                .scheme(name: "BetterAuthSwiftUI",
                                        shared: true,
                                        buildAction: .buildAction(targets: ["BetterAuthSwiftUI"]),
                                        runAction: .runAction(configuration: "Debug"),
                                        archiveAction: .archiveAction(configuration: "Release")),
                                .scheme(name: "BetterAuthMagicLink",
                                        shared: true,
                                        buildAction: .buildAction(targets: ["BetterAuthMagicLink"]),
                                        runAction: .runAction(configuration: "Debug"),
                                        archiveAction: .archiveAction(configuration: "Release")),
                                .scheme(name: "BetterAuthOrganization",
                                        shared: true,
                                        buildAction: .buildAction(targets: ["BetterAuthOrganization"]),
                                        runAction: .runAction(configuration: "Debug"),
                                        archiveAction: .archiveAction(configuration: "Release")),
                                .scheme(name: "BetterAuth-Package",
                                        shared: true,
                                        buildAction: .buildAction(targets: ["BetterAuth",
                                                                            "BetterAuthEmailPassword",
                                                                            "BetterAuthUsername",
                                                                            "BetterAuthAnonymous",
                                                                            "BetterAuthSocialOAuth",
                                                                            "BetterAuthAppleSignIn",
                                                                            "BetterAuthMagicLink",
                                                                            "BetterAuthSwiftUI",
                                                                            "BetterAuthOrganization",
                                                                            "BetterAuthTestHelpers",
                                                                            "BetterAuthSwiftTests",
                                                                            "BetterAuthOrganizationTests",
                                                                            "BetterAuthMagicLinkTests",
                                                                            "BetterAuthAuthModulesTests"]),
                                        testAction: .targets([.testableTarget(target: "BetterAuthSwiftTests"),
                                                              .testableTarget(target: "BetterAuthOrganizationTests"),
                                                              .testableTarget(target: "BetterAuthMagicLinkTests"),
                                                              .testableTarget(target: "BetterAuthAuthModulesTests")],
                                                             configuration: "Debug"),
                                        runAction: .runAction(configuration: "Debug"),
                                        archiveAction: .archiveAction(configuration: "Release"))],
                      additionalFiles: ["Package.swift",
                                        ".swiftlint.yml",
                                        ".swiftformat",
                                        "Scripts/**"],
                      resourceSynthesizers: [])
