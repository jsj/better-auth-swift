import Foundation
import ProjectDescription

public enum ExampleEnvironmentDefaults {
    private static let dotEnv: [String: String] = {
        let envPath = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // ProjectDescriptionHelpers
            .deletingLastPathComponent() // Tuist
            .deletingLastPathComponent() // ios
            .appendingPathComponent(".env")

        guard let contents = try? String(contentsOf: envPath, encoding: .utf8) else {
            return [:]
        }

        var result: [String: String] = [:]
        for line in contents.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
            let parts = trimmed.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { continue }

            let key = String(parts[0]).trimmingCharacters(in: .whitespaces)
            var value = String(parts[1]).trimmingCharacters(in: .whitespaces)
            if (value.hasPrefix("\"") && value.hasSuffix("\"")) ||
                (value.hasPrefix("'") && value.hasSuffix("'")) {
                value = String(value.dropFirst().dropLast())
            }

            result[key] = value
        }

        return result
    }()

    private static let defaults: [String: String] = [
        "TUIST_API_BASE_URL": "http://127.0.0.1:8787",
        "TUIST_DEVELOPMENT_TEAM": "",
        "TUIST_CODE_SIGN_STYLE": "Automatic"
    ]

    public static let apiBaseURL = env("TUIST_API_BASE_URL")
    public static let codeSignStyle = env("TUIST_CODE_SIGN_STYLE")
    public static let developmentTeam = optionalEnv("TUIST_DEVELOPMENT_TEAM")

    private static func env(_ key: String) -> String {
        if let value = ProcessInfo.processInfo.environment[key], !value.isEmpty {
            return value
        }
        if let value = dotEnv[key], !value.isEmpty {
            return value
        }
        return defaults[key] ?? ""
    }

    private static func optionalEnv(_ key: String) -> String? {
        let value = env(key)
        return value.isEmpty ? nil : value
    }

    public static let environmentArguments = Arguments.arguments(
        environmentVariables: [
            "API_BASE_URL": EnvironmentVariable.environmentVariable(
                value: apiBaseURL,
                isEnabled: true
            )
        ]
    )
}
