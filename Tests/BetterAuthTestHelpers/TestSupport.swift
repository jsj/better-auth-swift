import BetterAuth
import Foundation

public struct MockTransport: BetterAuthTransport {
    public let handler: @Sendable (URLRequest) async throws -> (Data, URLResponse)

    public init(handler: @escaping @Sendable (URLRequest) async throws -> (Data, URLResponse)) {
        self.handler = handler
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await handler(request)
    }
}

public actor SequencedMockTransport: BetterAuthTransport {
    public enum Entry: Sendable {
        case raw(Data, Int)
        case handler(@Sendable (URLRequest) throws -> (Data, URLResponse))

        public static func response(statusCode: Int, jsonObject: Any) -> Entry {
            do {
                return .raw(try JSONSerialization.data(withJSONObject: jsonObject), statusCode)
            } catch {
                return .handler { _ in
                    throw TestFailure("Invalid JSON mock response: \(error)")
                }
            }
        }

        public static func response(statusCode: Int, encodable: some Encodable) -> Entry {
            do {
                return .raw(try encodeJSON(encodable), statusCode)
            } catch {
                return .handler { _ in
                    throw TestFailure("Failed to encode mock response: \(error)")
                }
            }
        }
    }

    private var entries: [Entry]

    public init(_ entries: [Entry]) {
        self.entries = entries
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard !entries.isEmpty else {
            throw TestFailure("No mock responses left for request: \(request.url?.absoluteString ?? "nil")")
        }

        let entry = entries.removeFirst()
        switch entry {
        case let .raw(data, statusCode):
            return response(for: request, statusCode: statusCode, data: data)

        case let .handler(handler):
            return try handler(request)
        }
    }
}

public func emptyResponse(for request: URLRequest) -> (Data, URLResponse) {
    response(for: request, statusCode: 200, data: Data())
}

public func encodeJSON(_ value: some Encodable) throws -> Data {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    return try encoder.encode(value)
}

public struct TestFailure: Error, CustomStringConvertible, LocalizedError, Sendable {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String {
        message
    }

    public var errorDescription: String? {
        message
    }
}

public func expect(_ condition: @autoclosure () -> Bool,
                   _ message: @autoclosure () -> String = "Expectation failed") throws
{
    guard condition() else {
        throw TestFailure(message())
    }
}

public func response(for request: URLRequest, statusCode: Int, data: Data) -> (Data, URLResponse) {
    let response = HTTPURLResponse(url: request.url ?? URL(string: "https://example.com")!,
                                   statusCode: statusCode,
                                   httpVersion: nil,
                                   headerFields: nil)!
    return (data, response)
}

public func secondsBetween(_ lhs: Date?, _ rhs: Date?) -> TimeInterval {
    guard let lhs, let rhs else { return .infinity }
    return abs(lhs.timeIntervalSince1970 - rhs.timeIntervalSince1970)
}

public func waitForCondition(timeout: TimeInterval = 1,
                             pollInterval: TimeInterval = 0.005,
                             _ condition: @escaping @Sendable () -> Bool) async throws
{
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if condition() { return }
        try await Task.sleep(for: .seconds(pollInterval))
    }
    throw TestFailure("Condition not met within \(timeout) seconds")
}

public struct SignOutResult: Encodable, Sendable {
    public let success: Bool

    public init(success: Bool) {
        self.success = success
    }
}

public struct ProtectedResponse: Codable, Equatable, Sendable {
    public let email: String
    public let username: String?

    public init(email: String, username: String? = nil) {
        self.email = email
        self.username = username
    }
}

public final class Locked<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    public init(_ value: Value) {
        self.value = value
    }

    public func withLock<T>(_ body: (inout Value) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}

public final class CapturingLogger: BetterAuthLogger, @unchecked Sendable {
    private let messages = Locked<[String]>([])

    public init() {}

    public func log(level: BetterAuthLogLevel, message: String, file: String, function: String, line: UInt) {
        messages.withLock { $0.append(message) }
    }

    public var capturedMessages: [String] {
        messages.withLock { $0 }
    }
}
