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
    public let transition: BetterAuthSessionTransition?

    public init(event: AuthChangeEvent,
                session: BetterAuthSession?,
                transition: BetterAuthSessionTransition? = nil)
    {
        self.event = event
        self.session = session
        self.transition = transition
    }
}

public typealias AuthStateChangeListener = @Sendable (AuthStateChange) async -> Void

public protocol AuthStateChangeRegistration: Sendable {
    func remove()
}

private actor AuthEventDeliveryQueue {
    func deliver(stateChange: AuthStateChange,
                 listeners: [AuthStateChangeListener]) async
    {
        for listener in listeners {
            await listener(stateChange)
        }
    }
}

private enum AuthEventNotifier {
    static func post(_ stateChange: AuthStateChange) {
        NotificationCenter.default.post(name: .betterAuthStateDidChange,
                                        object: nil,
                                        userInfo: ["event": stateChange.event.rawValue,
                                                   "session": stateChange.session as Any])
    }
}

public final class AuthEventEmitter: @unchecked Sendable {
    private let lock = NSLock()
    private let deliveryQueue = AuthEventDeliveryQueue()
    private var listeners: [UUID: AuthStateChangeListener] = [:]
    private var continuations: [UUID: AsyncStream<AuthStateChange>.Continuation] = [:]
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
                AuthEventNotifier.post(latestStateChange)
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

    func emit(_ event: AuthChangeEvent,
              session: BetterAuthSession?,
              transition: BetterAuthSessionTransition? = nil)
    {
        let stateChange = AuthStateChange(event: event, session: session, transition: transition)
        yield(stateChange)
    }

    func yield(_ stateChange: AuthStateChange) {
        lock.lock()
        latestStateChange = stateChange
        let currentListeners = Array(listeners.values)
        let currentContinuations = Array(continuations.values)
        lock.unlock()

        for continuation in currentContinuations {
            continuation.yield(stateChange)
        }
        AuthEventNotifier.post(stateChange)

        guard !currentListeners.isEmpty else { return }
        Task {
            await deliveryQueue.deliver(stateChange: stateChange,
                                        listeners: currentListeners)
        }
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
            emitter = nil
        }

        deinit {
            remove()
        }
    }
}

public extension Notification.Name {
    static let betterAuthStateDidChange = Notification.Name("BetterAuth.stateDidChange")
}
