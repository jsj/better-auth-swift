# Session Lifecycle

The session lifecycle API lives on `client.auth.lifecycle`. The older flat
methods on `client.auth` remain available for compatibility.

## Restore at app launch

Prefer `restoreOnLaunch()` when bootstrapping an app because it returns a typed `BetterAuthRestoreResult`.

```swift
let result = try await client.auth.lifecycle.restoreOnLaunch()

switch result {
case .noStoredSession:
    // Show signed-out UI.
case .restored(let session, _, let refresh):
    // Show signed-in UI. `refresh` tells whether refresh was skipped, completed, or deferred.
case .cleared:
    // Stored session was invalid and local state was cleared.
}
```

For a session-only compatibility path, use:

```swift
let session = try await client.auth.lifecycle.restoreOrRefresh()
```

If you need to inspect the stored session separately before applying it to in-memory state, use:

```swift
let stored = try await client.auth.loadStoredSession()
try await client.auth.applyRestoredSession(stored)
```

## Read current in-memory session

```swift
let session = await client.auth.lifecycle.current()
```

## Observe auth state

```swift
for await change in client.auth.lifecycle.authStateChanges {
    print(change.event, change.session as Any)
}
```

For callback-style observation:

```swift
let registration = client.auth.lifecycle.onAuthStateChange.on { change in
    print(change.event)
}
```

Keep the returned registration alive for as long as you want to receive events.

## Refresh

```swift
let refreshed = try await client.auth.lifecycle.refresh()
let freshIfNeeded = try await client.auth.lifecycle.refreshIfNeeded()
```

## Fetch the latest server state

```swift
let session = try await client.auth.lifecycle.fetchCurrent()
```

This asks the backend for the current session payload and synchronizes local state.

## Sign out

```swift
try await client.auth.lifecycle.signOut()
```

By default this signs out remotely and clears local state. To clear local state only:

```swift
try await client.auth.lifecycle.signOut(remotely: false)
```

## Session management

```swift
let sessions = try await client.auth.sessions.list()
let devices = try await client.auth.sessions.listDevices()
let jwt = try await client.auth.sessions.jwt()
let jwks = try await client.auth.sessions.jwks()
try await client.auth.sessions.revokeOthers()
try await client.auth.sessions.revokeAll()
```

Use `revokeSession(token:)`, `setActiveDeviceSession(_:)`, and `revokeDeviceSession(_:)` for targeted device/session control.

## Incoming URLs

```swift
let parsed = await client.auth.parseIncomingURL(url)
let handled = try await client.auth.lifecycle.handleIncomingURL(url)
```

The URL helpers cover OAuth callbacks, generic OAuth callbacks, magic links, and email/OTP verification callbacks configured through the SDK.

## Persistence

The SDK persists the active session using the configured session store, which defaults to `KeychainSessionStore`. You can provide a custom `BetterAuthSessionStore` or use `InMemorySessionStore` for tests.
