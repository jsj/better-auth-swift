import Foundation

public enum AuthChangeEvent: String, Sendable {
    case initialSession
    case signedIn
    case signedOut
    case tokenRefreshed
    case userUpdated
    case sessionExpired
}

public struct AuthStateChange: Sendable, Equatable {
    public let event: AuthChangeEvent
    public let session: BetterAuthSession?

    public init(event: AuthChangeEvent, session: BetterAuthSession?) {
        self.event = event
        self.session = session
    }
}

public typealias AuthStateChangeListener = @Sendable (AuthChangeEvent, BetterAuthSession?) -> Void

public protocol AuthStateChangeRegistration: Sendable {
    func remove()
}

/// Thread-safe event emitter backed by a lock.
///
/// Safety invariant for `@unchecked Sendable`: all mutable state is accessed only
/// while `lock` is held, and emitted listener/continuation snapshots are invoked
/// after releasing the lock.
public final class AuthEventEmitter: @unchecked Sendable {
    private let lock = NSLock()
    private var listeners: [UUID: AuthStateChangeListener] = [:]
    private var continuations: [UUID: AsyncStream<AuthStateChange>.Continuation] =
        [:]
    private var latestStateChange: AuthStateChange?

    public init() {}

    @discardableResult
    public func on(_ listener: @escaping AuthStateChangeListener) -> AuthStateChangeRegistration {
        let id = UUID()
        lock.lock()
        listeners[id] = listener
        lock.unlock()
        return Registration(emitter: self, id: id)
    }

    public var events: AsyncStream<AuthStateChange> {
        let id = UUID()
        return AsyncStream { continuation in
            lock.lock()
            let latestStateChange = latestStateChange
            continuations[id] = continuation
            lock.unlock()
            if let latestStateChange {
                continuation.yield(latestStateChange)
            }
            continuation.onTermination = { [weak self] _ in
                self?.removeContinuation(id)
            }
        }
    }

    public var stateChanges: AsyncStream<AuthStateChange> {
        events
    }

    public var latest: AuthStateChange? {
        lock.lock()
        defer { lock.unlock() }
        return latestStateChange
    }

    func emit(_ event: AuthChangeEvent, session: BetterAuthSession?) {
        let stateChange = AuthStateChange(event: event, session: session)
        lock.lock()
        latestStateChange = stateChange
        let currentListeners = listeners.values
        let currentContinuations = continuations.values
        lock.unlock()

        for listener in currentListeners {
            listener(event, session)
        }
        for continuation in currentContinuations {
            continuation.yield(stateChange)
        }

        NotificationCenter.default.post(name: .betterAuthStateDidChange,
                                        object: nil,
                                        userInfo: ["event": event.rawValue,
                                                   "session": session as Any])
    }

    private func removeListener(_ id: UUID) {
        lock.lock()
        listeners.removeValue(forKey: id)
        lock.unlock()
    }

    private func removeContinuation(_ id: UUID) {
        lock.lock()
        continuations.removeValue(forKey: id)
        lock.unlock()
    }

    /// Safety invariant for `@unchecked Sendable`: `emitter` is weak and `id` is immutable.
    private final class Registration: AuthStateChangeRegistration, @unchecked Sendable {
        private weak var emitter: AuthEventEmitter?
        private let id: UUID

        init(emitter: AuthEventEmitter, id: UUID) {
            self.emitter = emitter
            self.id = id
        }

        func remove() {
            emitter?.removeListener(id)
        }
    }
}

public extension Notification.Name {
    static let betterAuthStateDidChange = Notification.Name("BetterAuth.stateDidChange")
}
