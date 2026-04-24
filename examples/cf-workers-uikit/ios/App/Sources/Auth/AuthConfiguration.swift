import Foundation

struct AuthConfiguration {
    let apiBaseURL: URL
    let source: Source

    enum Source {
        case infoPlist
        case developmentDefault
    }

    init(apiBaseURL: URL, source: Source) {
        self.apiBaseURL = apiBaseURL
        self.source = source
    }

    init(bundle: Bundle = .main, environment: ProcessInfo = .processInfo) throws {
        if let configuredURL = try Self.url(forKey: "API_BASE_URL",
                                            in: bundle,
                                            missingValueError: AuthConfigurationError
                                                .missingValue(key: "API_BASE_URL"))
        {
            apiBaseURL = configuredURL
            source = .infoPlist
            return
        }

        #if DEBUG
            if let developmentURL = try Self.url(forKey: "BETTER_AUTH_BASE_URL",
                                                 in: environment.environment,
                                                 missingValueError: AuthConfigurationError
                                                     .missingValue(key: "BETTER_AUTH_BASE_URL")) ??
                URL(string: "http://127.0.0.1:8787")
            {
                apiBaseURL = developmentURL
                source = .developmentDefault
                return
            }
        #endif

        throw AuthConfigurationError.missingValue(key: "API_BASE_URL")
    }

    var displayBaseURL: String {
        apiBaseURL.absoluteString
    }

    var statusMessage: String? {
        switch source {
        case .infoPlist:
            nil

        case .developmentDefault:
            "Using development default: \(displayBaseURL)"
        }
    }

    private static func url(forKey key: String,
                            in bundle: Bundle,
                            missingValueError: AuthConfigurationError) throws -> URL?
    {
        guard let rawValue = bundle.object(forInfoDictionaryKey: key) as? String else {
            return nil
        }

        return try url(forKey: key, rawValue: rawValue, missingValueError: missingValueError)
    }

    private static func url(forKey key: String,
                            in environment: [String: String],
                            missingValueError: AuthConfigurationError) throws -> URL?
    {
        guard let rawValue = environment[key] else {
            return nil
        }

        return try url(forKey: key, rawValue: rawValue, missingValueError: missingValueError)
    }

    private static func url(forKey key: String,
                            rawValue: String,
                            missingValueError: AuthConfigurationError) throws -> URL?
    {
        let trimmedValue = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedValue.isEmpty else {
            throw missingValueError
        }

        guard let url = URL(string: trimmedValue) else {
            throw AuthConfigurationError.invalidURL(key: key, value: rawValue)
        }

        return url
    }
}

enum AuthConfigurationError: LocalizedError {
    case missingValue(key: String)
    case invalidURL(key: String, value: String)

    var errorDescription: String? {
        switch self {
        case let .missingValue(key):
            "Missing configuration value: \(key)"

        case let .invalidURL(key, value):
            "Invalid URL for \(key): \(value)"
        }
    }
}
