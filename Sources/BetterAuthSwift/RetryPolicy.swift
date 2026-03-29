import Foundation

public struct RetryPolicy: Sendable {
    public let maxRetries: Int
    public let baseDelay: TimeInterval
    public let maxDelay: TimeInterval
    public let retryableStatusCodes: Set<Int>

    public init(
        maxRetries: Int = 2,
        baseDelay: TimeInterval = 0.5,
        maxDelay: TimeInterval = 10,
        retryableStatusCodes: Set<Int> = [408, 500, 502, 503, 504]
    ) {
        self.maxRetries = maxRetries
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.retryableStatusCodes = retryableStatusCodes
    }

    public static let none = RetryPolicy(maxRetries: 0)
    public static let `default` = RetryPolicy()

    public func delay(for attempt: Int) -> TimeInterval {
        min(baseDelay * pow(2, Double(attempt - 1)), maxDelay)
    }

    public func isRetryable(statusCode: Int) -> Bool {
        retryableStatusCodes.contains(statusCode)
    }

    public func isRetryable(error: Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else { return false }
        let retryableCodes: Set<Int> = [
            NSURLErrorTimedOut,
            NSURLErrorCannotConnectToHost,
            NSURLErrorCannotFindHost,
            NSURLErrorNetworkConnectionLost,
            NSURLErrorNotConnectedToInternet,
            NSURLErrorDNSLookupFailed,
        ]
        return retryableCodes.contains(nsError.code)
    }
}
