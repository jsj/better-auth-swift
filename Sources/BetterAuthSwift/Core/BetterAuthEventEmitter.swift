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
                 continuations: [AsyncStream<AuthStateChange>.Continuation],
                 listeners: [AuthStateChangeListener]) async
    {
        for continuation in continuations {
            continuation.yield(stateChange)
        }
        AuthEventNotifier.post(stateChange)
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

private final class AuthEventEmitterState: @unchecked Sendable {
    private let lock = NSLock()
    var listeners: [UUID: AuthStateChangeListener] = [:]
    var continuations: [UUID: AsyncStream<AuthStateChange>.Continuation] = [:]
    var latestStateChange: AuthStateChange?
    var listenerDeliveryTask: Task<Void, Never>?

    func withLock<T>(_ body: (AuthEventEmitterState) throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body(self)
    }
}

public final class AuthEventEmitter: Sendable {
    private let deliveryQueue = AuthEventDeliveryQueue()
    private let state = AuthEventEmitterState()

    public init() {}

    deinit {
        let continuations = state.withLock { state in
            let continuations = Array(state.continuations.values)
            state.continuations.removeAll()
            state.listeners.removeAll()
            state.listenerDeliveryTask?.cancel()
            state.listenerDeliveryTask = nil
            return continuations
        }
        continuations.forEach { $0.finish() }
    }

    @discardableResult
    public func on(_ listener: @escaping AuthStateChangeListener) -> AuthStateChangeRegistration {
        let id = UUID()
        state.withLock { $0.listeners[id] = listener }
        return Registration(emitter: self, id: id)
    }

    public var events: AsyncStream<AuthStateChange> {
        let id = UUID()
        return AsyncStream { continuation in
            let latestStateChange = state.withLock { state in
                let latestStateChange = state.latestStateChange
                state.continuations[id] = continuation
                return latestStateChange
            }
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
        state.withLock { $0.latestStateChange }
    }

    func emit(_ event: AuthChangeEvent,
              session: BetterAuthSession?,
              transition: BetterAuthSessionTransition? = nil)
    {
        let stateChange = AuthStateChange(event: event, session: session, transition: transition)
        yield(stateChange)
    }

    func yield(_ stateChange: AuthStateChange) {
        state.withLock { state in
            state.latestStateChange = stateChange
            let currentListeners = Array(state.listeners.values)
            let currentContinuations = Array(state.continuations.values)
            let previousDeliveryTask = state.listenerDeliveryTask
            state.listenerDeliveryTask = Task {
                await previousDeliveryTask?.value
                await deliveryQueue.deliver(stateChange: stateChange,
                                            continuations: currentContinuations,
                                            listeners: currentListeners)
            }
        }
    }

    private func removeListener(_ id: UUID) {
        _ = state.withLock { $0.listeners.removeValue(forKey: id) }
    }

    private func removeContinuation(_ id: UUID) {
        _ = state.withLock { $0.continuations.removeValue(forKey: id) }
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
