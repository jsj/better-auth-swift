import BetterAuth
import Foundation
import Testing

func assertRequestFailed(statusCode expectedStatusCode: Int,
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

func assertRequestFailedJSON(statusCode expectedStatusCode: Int,
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
