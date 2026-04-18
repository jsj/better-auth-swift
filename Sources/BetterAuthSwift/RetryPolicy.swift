import Foundation

public struct RetryPolicy: Sendable {
    public let maxRetries: Int
    public let baseDelay: TimeInterval
    public let maxDelay: TimeInterval
    public let retryableStatusCodes: Set<Int>
    public let jitterFactor: Double

    public init(maxRetries: Int = 2,
                baseDelay: TimeInterval = 0.5,
                maxDelay: TimeInterval = 10,
                retryableStatusCodes: Set<Int> = [408, 500, 502, 503, 504],
                jitterFactor: Double = 0.25)
    {
        self.maxRetries = maxRetries
        self.baseDelay = baseDelay
        self.maxDelay = maxDelay
        self.retryableStatusCodes = retryableStatusCodes
        self.jitterFactor = min(max(jitterFactor, 0), 1)
    }

    public static let none = RetryPolicy(maxRetries: 0)
    public static let `default` = RetryPolicy()

    public func delay(for attempt: Int) -> TimeInterval {
        let cappedBaseDelay = min(baseDelay * pow(2, Double(attempt - 1)), maxDelay)
        guard jitterFactor > 0 else { return cappedBaseDelay }
        let lowerBound = cappedBaseDelay * (1 - jitterFactor)
        let upperBound = cappedBaseDelay
        return Double.random(in: lowerBound ... upperBound)
    }

    public func isRetryable(statusCode: Int) -> Bool {
        retryableStatusCodes.contains(statusCode)
    }

    public func isRetryable(error: Error) -> Bool {
        let nsError = error as NSError
        guard nsError.domain == NSURLErrorDomain else { return false }
        let retryableCodes: Set<Int> = [NSURLErrorTimedOut,
                                        NSURLErrorCannotConnectToHost,
                                        NSURLErrorCannotFindHost,
                                        NSURLErrorNetworkConnectionLost,
                                        NSURLErrorNotConnectedToInternet,
                                        NSURLErrorDNSLookupFailed]
        return retryableCodes.contains(nsError.code)
    }
}
