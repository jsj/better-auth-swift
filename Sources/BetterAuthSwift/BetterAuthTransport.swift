import Foundation

public protocol BetterAuthTransport: Sendable {
    func execute(_ request: URLRequest) async throws -> (Data, URLResponse)
}

public struct URLSessionTransport: BetterAuthTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await session.data(for: request)
    }
}
