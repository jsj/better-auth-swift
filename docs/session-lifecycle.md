# Session Lifecycle

The core session API lives on `client.auth`.

## Restore existing state

```swift
let session = try await client.auth.restoreOrRefreshSession()
```

This is the best default for app launch. It restores a stored session if possible and refreshes it when needed.

If you need a synchronous read from storage without crossing the session manager actor boundary, use:

```swift
let stored = try client.auth.loadStoredSession()
```

If you later want to apply that session to the manager's in-memory state, call:

```swift
try await client.auth.applyRestoredSession(stored)
```

## Read current in-memory session

```swift
let session = await client.auth.currentSession()
```

## Refresh explicitly

```swift
let session = try await client.auth.refreshSession()
```

Use this when you know you want a refresh now.

## Refresh only if needed

```swift
let session = try await client.auth.refreshSessionIfNeeded()
```

Use this if you want the SDK to check whether the current session is still fresh before refreshing.

## Fetch the latest server state

```swift
let session = try await client.auth.fetchCurrentSession()
```

This asks the backend for the current session payload and synchronizes local state.

## Sign out

```swift
try await client.auth.signOut()
```

By default this signs out remotely and clears local state.

If you only want to clear local state:

```swift
try await client.auth.signOut(remotely: false)
```

## What is persisted

The SDK persists the active session using the configured session store, which defaults to a keychain-backed store.
