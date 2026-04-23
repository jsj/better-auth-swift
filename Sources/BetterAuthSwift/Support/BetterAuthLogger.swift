import Foundation
import os

public enum BetterAuthLogLevel: Int, Sendable, Comparable {
    case debug = 0
    case info = 1
    case warning = 2
    case error = 3

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public protocol BetterAuthLogger: Sendable {
    func log(level: BetterAuthLogLevel, message: String, file: String, function: String, line: UInt)
}

public extension BetterAuthLogger {
    func debug(_ message: String, file: String = #fileID, function: String = #function, line: UInt = #line) {
        log(level: .debug, message: message, file: file, function: function, line: line)
    }

    func info(_ message: String, file: String = #fileID, function: String = #function, line: UInt = #line) {
        log(level: .info, message: message, file: file, function: function, line: line)
    }

    func warning(_ message: String, file: String = #fileID, function: String = #function, line: UInt = #line) {
        log(level: .warning, message: message, file: file, function: function, line: line)
    }

    func error(_ message: String, file: String = #fileID, function: String = #function, line: UInt = #line) {
        log(level: .error, message: message, file: file, function: function, line: line)
    }
}

public struct OSLogBetterAuthLogger: BetterAuthLogger {
    private let logger: os.Logger
    public let minimumLevel: BetterAuthLogLevel

    public init(subsystem: String = "com.better-auth.swift",
                category: String = "Auth",
                minimumLevel: BetterAuthLogLevel = .debug)
    {
        self.logger = os.Logger(subsystem: subsystem, category: category)
        self.minimumLevel = minimumLevel
    }

    public func log(level: BetterAuthLogLevel, message: String, file: String, function: String, line: UInt) {
        guard level >= minimumLevel else { return }
        switch level {
        case .debug:
            logger.debug("\(message, privacy: .private)")

        case .info:
            logger.info("\(message, privacy: .private)")

        case .warning:
            logger.warning("\(message, privacy: .private)")

        case .error:
            logger.error("\(message, privacy: .private)")
        }
    }
}

public struct PrintBetterAuthLogger: BetterAuthLogger {
    public let minimumLevel: BetterAuthLogLevel

    public init(minimumLevel: BetterAuthLogLevel = .debug) {
        self.minimumLevel = minimumLevel
    }

    public func log(level: BetterAuthLogLevel, message: String, file: String, function: String, line: UInt) {
        guard level >= minimumLevel else { return }
        let prefix = switch level {
        case .debug: "[DEBUG]"
        case .info: "[INFO]"
        case .warning: "[WARN]"
        case .error: "[ERROR]"
        }
        print("\(prefix) [BetterAuth] \(message) (\(file):\(line))")
    }
}
