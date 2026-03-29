import Foundation

public enum AuthChangeEvent: String, Sendable {
    case initialSession
    case signedIn
    case signedOut
    case tokenRefreshed
    case userUpdated
    case sessionExpired
}

public typealias AuthStateChangeListener = @Sendable (AuthChangeEvent, BetterAuthSession?) -> Void

public protocol AuthStateChangeRegistration: Sendable {
    func remove()
}

public final class AuthEventEmitter: @unchecked Sendable {
    private let lock = NSLock()
    private var listeners: [UUID: AuthStateChangeListener] = [:]
    private var continuations: [UUID: AsyncStream<(event: AuthChangeEvent, session: BetterAuthSession?)>.Continuation] = [:]

    public init() {}

    @discardableResult
    public func on(_ listener: @escaping AuthStateChangeListener) -> AuthStateChangeRegistration {
        let id = UUID()
        lock.lock()
        listeners[id] = listener
        lock.unlock()
        return Registration(emitter: self, id: id)
    }

    public var events: AsyncStream<(event: AuthChangeEvent, session: BetterAuthSession?)> {
        let id = UUID()
        return AsyncStream { continuation in
            lock.lock()
            continuations[id] = continuation
            lock.unlock()
            continuation.onTermination = { [weak self] _ in
                self?.removeContinuation(id)
            }
        }
    }

    func emit(_ event: AuthChangeEvent, session: BetterAuthSession?) {
        lock.lock()
        let currentListeners = listeners.values
        let currentContinuations = continuations.values
        lock.unlock()

        for listener in currentListeners {
            listener(event, session)
        }
        for continuation in currentContinuations {
            continuation.yield((event: event, session: session))
        }

        NotificationCenter.default.post(
            name: .betterAuthStateDidChange,
            object: nil,
            userInfo: [
                "event": event.rawValue,
                "session": session as Any,
            ]
        )
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
