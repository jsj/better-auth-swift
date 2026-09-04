import BetterAuthTestHelpers
import Foundation
import Testing
@testable import BetterAuth

struct SessionRaceRegressionTests {
    @Test(arguments: [false, true])
    func lateRefreshCannotUndoSignOut(fetch: Bool) async throws {
        let transport = SuspendedSessionTransport()
        let store = InMemorySessionStore()
        let manager = makeManager(transport: transport, store: store)
        let old = session("old")
        try await manager.updateSession(old)
        var requests = transport.requests.makeAsyncIterator()
        let operation = Task { try await fetch ? manager.fetchCurrentSession() : manager.refreshSession() }
        _ = await requests.next()
        try await manager.signOut(remotely: false)
        await transport.complete(with: old)
        await #expect(throws: CancellationError.self) { try await operation.value }
        #expect(await manager.currentSession() == nil)
        #expect(try store.loadSession(for: "race-test") == nil)
        #expect(manager.currentAuthState?.event == .signedOut)
    }

    @Test(arguments: [false, true])
    func staleRefreshCannotReplaceOrClearNewSession(unauthorized: Bool) async throws {
        let transport = SuspendedSessionTransport()
        let manager = makeManager(transport: transport)
        try await manager.updateSession(session("old"))
        var requests = transport.requests.makeAsyncIterator()
        let operation = Task { try await manager.refreshSession() }
        _ = await requests.next()
        let newer = session("new")
        try await manager.updateSession(newer)
        await transport.complete(with: session("old-refreshed"), statusCode: unauthorized ? 401 : 200)
        await #expect(throws: CancellationError.self) { try await operation.value }
        #expect(await manager.currentSession() == newer)
        #expect(manager.currentAuthState?.session == newer)
    }

    @Test
    func newSessionDoesNotJoinPreviousSessionsRefresh() async throws {
        let transport = SuspendedSessionTransport()
        let manager = makeManager(transport: transport)
        try await manager.updateSession(session("old"))
        var requests = transport.requests.makeAsyncIterator()
        let oldRefresh = Task { try await manager.refreshSession() }
        _ = await requests.next()
        try await manager.updateSession(session("new"))
        let newRefresh = Task { try await manager.refreshSession() }
        let request = await requests.next()
        #expect(request?.value(forHTTPHeaderField: "Authorization") == "Bearer new")
        await transport.complete(with: session("old-refreshed"))
        await #expect(throws: CancellationError.self) { try await oldRefresh.value }
        let refreshed = session("new-refreshed")
        await transport.complete(with: refreshed)
        #expect(try await newRefresh.value == refreshed)
        #expect(await manager.currentSession() == refreshed)
    }

    @Test
    func shutdownInvalidatesPendingRefresh() async throws {
        let transport = SuspendedSessionTransport()
        let manager = makeManager(transport: transport)
        let old = session("old")
        try await manager.updateSession(old)
        var requests = transport.requests.makeAsyncIterator()
        let operation = Task { try await manager.refreshSession() }
        _ = await requests.next()
        await manager.shutdown()
        await transport.complete(with: session("refreshed"))
        await #expect(throws: CancellationError.self) { try await operation.value }
        #expect(await manager.currentSession() == old)
        #expect(await manager.autoRefreshTask == nil)
    }

    @Test
    func failedRemoteSignOutStillClearsLocalSession() async throws {
        let transport = SuspendedSessionTransport()
        let store = InMemorySessionStore()
        let manager = makeManager(transport: transport, store: store)
        try await manager.updateSession(session("old"))
        var requests = transport.requests.makeAsyncIterator()
        let signOut = Task { try await manager.signOut() }
        let request = await requests.next()
        #expect(request?.value(forHTTPHeaderField: "Authorization") == "Bearer old")
        #expect(await manager.currentSession() == nil)
        #expect(try store.loadSession(for: "race-test") == nil)
        await transport.fail(URLError(.notConnectedToInternet))
        await #expect(throws: URLError.self) { try await signOut.value }
        #expect(await manager.currentSession() == nil)
        #expect(manager.currentAuthState?.event == .signedOut)
    }

    @Test(arguments: [false, true])
    func managerDeallocatesWithAndWithoutShutdown(shutdown: Bool) async throws {
        var manager: BetterAuthSessionManager? = makeManager(transport: SuspendedSessionTransport(), autoRefresh: true)
        weak var reference = manager
        try await manager?.updateSession(session("old"))
        if shutdown {
            await manager?.shutdown()
        }
        manager = nil
        #expect(reference == nil)
    }

    @Test(arguments: ["profile", "revokeAll"])
    func routineRefreshDoesNotDiscardSessionOperations(operation: String) async throws {
        let transport = SuspendedSessionTransport()
        let manager = makeManager(transport: transport)
        try await manager.updateSession(session("old"))
        var requests = transport.requests.makeAsyncIterator()
        let mutation = Task {
            if operation == "profile" {
                _ = try await manager.updateUser(.init(name: "Updated"))
            } else {
                _ = try await manager.revokeSessions()
            }
        }
        _ = await requests.next()
        let refresh = Task { try await manager.refreshSession() }
        _ = await requests.next()
        await transport.complete(with: session("refreshed", userID: "old"), index: 1)
        _ = try await refresh.value
        let data = operation == "profile"
            ? Data(#"{"status":true,"user":{"id":"old","name":"Updated"}}"#.utf8)
            : Data(#"{"status":true}"#.utf8)
        await transport.complete(data: data)
        try await mutation.value
        if operation == "profile" {
            #expect(await manager.currentSession()?.session.accessToken == "refreshed")
            #expect(await manager.currentSession()?.user.name == "Updated")
        } else {
            #expect(await manager.currentSession() == nil)
        }
    }

    @Test(arguments: [false, true])
    func lateSessionResponsePreservesNewProfile(fetch: Bool) async throws {
        let transport = SuspendedSessionTransport()
        let manager = makeManager(transport: transport)
        try await manager.updateSession(session("old"))
        var requests = transport.requests.makeAsyncIterator()
        let refresh = Task { try await fetch ? manager.fetchCurrentSession() : manager.refreshSession() }
        _ = await requests.next()
        let profile = Task { try await manager.updateUser(.init(name: "Updated")) }
        _ = await requests.next()
        await transport.complete(data: Data(#"{"status":true,"user":{"id":"old","name":"Updated"}}"#.utf8), index: 1)
        _ = try await profile.value
        await transport.complete(with: session("refreshed", userID: "old"))
        let result = try await refresh.value
        #expect(result.session.accessToken == "refreshed")
        #expect(result.user.name == "Updated")
        #expect(await manager.currentSession()?.user.name == "Updated")
    }

    @Test
    func firedTimerDoesNotRetainManagerDuringUnresponsiveRefresh() async throws {
        let transport = SuspendedSessionTransport()
        var manager: BetterAuthSessionManager? = makeManager(transport: transport, autoRefresh: true)
        weak var reference = manager
        var requests = transport.requests.makeAsyncIterator()
        let expiring = BetterAuthSession(session: .init(id: "s", userId: "u", accessToken: "token",
                                                        expiresAt: Date().addingTimeInterval(60)), user: .init(id: "u"))
        try await manager?.updateSession(expiring)
        _ = await requests.next()
        let refresh = await manager?.inFlightRefreshTask
        await manager?.shutdown()
        manager = nil
        #expect(reference == nil)
        await transport.complete(with: expiring)
        await #expect(throws: CancellationError.self) { try await refresh?.value }
    }

    private func makeManager(transport: any BetterAuthTransport,
                             store: any BetterAuthSessionStore = InMemorySessionStore(),
                             autoRefresh: Bool = false) -> BetterAuthSessionManager
    {
        BetterAuthSessionManager(configuration: .init(baseURL: URL(string: "https://example.com")!,
                                                      storage: .init(key: "race-test"),
                                                      autoRefreshToken: autoRefresh),
                                 sessionStore: store, transport: transport)
    }

    private func session(_ token: String, userID: String? = nil) -> BetterAuthSession {
        BetterAuthSession(session: .init(id: token, userId: userID ?? token, accessToken: token,
                                         expiresAt: Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) +
                                             3600)),
                          user: .init(id: userID ?? token))
    }
}

/// Holds responses until the test releases them; deliberately ignores cancellation
/// to prove that session-generation checks protect against late transports too.
private actor SuspendedSessionTransport: BetterAuthTransport {
    nonisolated let requests: AsyncStream<URLRequest>
    private let events: AsyncStream<URLRequest>.Continuation
    private var pending: [(URLRequest, CheckedContinuation<(Data, URLResponse), any Error>)] = []

    init() {
        (requests, events) = AsyncStream.makeStream()
    }

    func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await withCheckedThrowingContinuation { continuation in
            pending.append((request, continuation))
            events.yield(request)
        }
    }

    func complete(with session: BetterAuthSession, statusCode: Int = 200, index: Int = 0) {
        do {
            complete(data: try encodeJSON(session), statusCode: statusCode, index: index)
        } catch {
            pending.remove(at: index).1.resume(throwing: error)
        }
    }

    func complete(data: Data, statusCode: Int = 200, index: Int = 0) {
        let (request, continuation) = pending.remove(at: index)
        continuation.resume(returning: response(for: request, statusCode: statusCode, data: data))
    }

    func fail(_ error: any Error) {
        pending.removeFirst().1.resume(throwing: error)
    }
}
