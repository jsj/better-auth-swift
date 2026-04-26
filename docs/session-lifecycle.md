# Session Lifecycle

The core session API lives on `client.auth`.

## Restore at app launch

Prefer `restoreSessionOnLaunch()` when bootstrapping an app because it returns a typed `BetterAuthRestoreResult`.

```swift
let result = try await client.auth.restoreSessionOnLaunch()

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
let session = try await client.auth.restoreOrRefreshSession()
```

If you need to inspect the stored session separately before applying it to in-memory state, use:

```swift
let stored = try await client.auth.loadStoredSession()
try await client.auth.applyRestoredSession(stored)
```

## Read current in-memory session

```swift
let session = await client.auth.currentSession()
```

## Observe auth state

```swift
for await change in client.auth.authStateChanges {
    print(change.event, change.session as Any)
}
```

For callback-style observation:

```swift
let registration = client.auth.onAuthStateChange.on { change in
    print(change.event)
}
```

Keep the returned registration alive for as long as you want to receive events.

## Refresh

```swift
let refreshed = try await client.auth.refreshSession()
let freshIfNeeded = try await client.auth.refreshSessionIfNeeded()
```

## Fetch the latest server state

```swift
let session = try await client.auth.fetchCurrentSession()
```

This asks the backend for the current session payload and synchronizes local state.

## Sign out

```swift
try await client.auth.signOut()
```

By default this signs out remotely and clears local state. To clear local state only:

```swift
try await client.auth.signOut(remotely: false)
```

## Session management

```swift
let sessions = try await client.auth.listSessions()
let devices = try await client.auth.listDeviceSessions()
let jwt = try await client.auth.getSessionJWT()
let jwks = try await client.auth.getJWKS()
try await client.auth.revokeOtherSessions()
try await client.auth.revokeSessions()
```

Use `revokeSession(token:)`, `setActiveDeviceSession(_:)`, and `revokeDeviceSession(_:)` for targeted device/session control.

## Incoming URLs

```swift
let parsed = client.auth.parseIncomingURL(url)
let handled = try await client.auth.handleIncomingURL(url)
```

The URL helpers cover OAuth callbacks, generic OAuth callbacks, magic links, and email/OTP verification callbacks configured through the SDK.

## Persistence

The SDK persists the active session using the configured session store, which defaults to `KeychainSessionStore`. You can provide a custom `BetterAuthSessionStore` or use `InMemorySessionStore` for tests.
