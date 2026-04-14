import Foundation
import Testing
import BetterAuth

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
    public enum Entry {
        case raw(Data, Int)
        case handler(@Sendable (URLRequest) throws -> (Data, URLResponse))

        public static func response(statusCode: Int, jsonObject: Any) -> Entry {
            .raw(try! JSONSerialization.data(withJSONObject: jsonObject), statusCode)
        }

        public static func response(statusCode: Int, encodable: some Encodable) -> Entry {
            .raw(try! encodeJSON(encodable), statusCode)
        }
    }

    private var entries: [Entry]

    public init(_ entries: [Entry]) {
        self.entries = entries
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard !entries.isEmpty else {
            fatalError("No mock responses left")
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

public func assertRequestFailed(statusCode expectedStatusCode: Int,
                                message expectedMessage: String?,
                                fileID: String = #fileID,
                                filePath: String = #filePath,
                                line: Int = #line,
                                column: Int = #column,
                                operation: () async throws -> some Any) async
{
    let sourceLocation = SourceLocation(fileID: fileID, filePath: filePath, line: line, column: column)
    do {
        _ = try await operation()
        Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: sourceLocation)
    } catch let BetterAuthError.requestFailed(statusCode, message, _, _) {
        #expect(statusCode == expectedStatusCode, sourceLocation: sourceLocation)
        #expect(message == expectedMessage, sourceLocation: sourceLocation)
    } catch {
        Issue.record("Expected BetterAuthError.requestFailed but got \(error)", sourceLocation: sourceLocation)
    }
}

public func assertRequestFailedJSON(statusCode expectedStatusCode: Int,
                                    expectedJSON: [String: String],
                                    fileID: String = #fileID,
                                    filePath: String = #filePath,
                                    line: Int = #line,
                                    column: Int = #column,
                                    operation: () async throws -> some Any) async
{
    let sourceLocation = SourceLocation(fileID: fileID, filePath: filePath, line: line, column: column)
    do {
        _ = try await operation()
        Issue.record("Expected BetterAuthError.requestFailed", sourceLocation: sourceLocation)
    } catch let BetterAuthError.requestFailed(statusCode, message, _, response) {
        #expect(statusCode == expectedStatusCode, sourceLocation: sourceLocation)
        if let expectedMessage = expectedJSON["message"] {
            #expect(message == expectedMessage || response?.message == expectedMessage, sourceLocation: sourceLocation)
        }
        if let expectedCode = expectedJSON["code"] {
            #expect(response?.code == expectedCode, sourceLocation: sourceLocation)
        }
    } catch {
        Issue.record("Expected BetterAuthError.requestFailed but got \(error)", sourceLocation: sourceLocation)
    }
}

public struct SignOutResult: Encodable {
    public let success: Bool

    public init(success: Bool) {
        self.success = success
    }
}

public struct ProtectedResponse: Codable, Equatable {
    public let email: String
    public let username: String?

    public init(email: String, username: String? = nil) {
        self.email = email
        self.username = username
    }
}
