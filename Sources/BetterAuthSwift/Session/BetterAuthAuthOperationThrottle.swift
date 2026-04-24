import Foundation

actor BetterAuthAuthOperationThrottle {
    private var lastAttempts: [String: Date] = [:]

    func check(operation: String,
               policy: BetterAuthConfiguration.AuthThrottlePolicy,
               now: Date = Date()) throws
    {
        if let lastAttempt = lastAttempts[operation] {
            let retryAfter = policy.minimumInterval - now.timeIntervalSince(lastAttempt)
            guard retryAfter <= 0 else {
                throw BetterAuthError.requestFailed(statusCode: 429,
                                                    message: "Client-side auth throttle is active. Try again later.",
                                                    errorCode: .tooManyRequests,
                                                    response: ServerErrorResponse(message: "Client-side auth throttle is active. Try again later.",
                                                                                  code: AuthErrorCode.tooManyRequests
                                                                                      .rawValue,
                                                                                  status: 429,
                                                                                  statusCode: 429))
            }
        }
        lastAttempts[operation] = now
    }
}
