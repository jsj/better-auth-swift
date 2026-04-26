# SwiftUI

Use `BetterAuthSwiftUI` when you want an observable wrapper around the core SDK.

## Setup

```swift
import BetterAuth
import BetterAuthSwiftUI

@MainActor
let authStore = AuthStore(
    client: BetterAuthClient(
        baseURL: URL(string: "https://your-api.example.com")!
    )
)
```

## Available state

`AuthStore` exposes:

- `session`
- `launchState`
- `lastRestoreResult`
- `isLoading`
- `statusMessage`
- `lastError`
- `lastUnderlyingError`

## App launch

```swift
await authStore.bootstrap()

switch authStore.launchState {
case .idle, .restoring:
    break
case .authenticated(let session):
    print("Signed in", session.user.id)
case .unauthenticated:
    print("Signed out")
case .recoverableFailure(let session):
    print("Using cached state", session as Any)
case .failed:
    print("Restore failed")
}
```

## Incoming URLs

```swift
.onOpenURL { url in
    Task { await authStore.handleIncomingURL(url) }
}
```

## Common lifecycle calls

```swift
await authStore.bootstrap()
await authStore.restore()
await authStore.refresh()
await authStore.fetchCurrentSession()
await authStore.signOut()
authStore.shutdown()
```

## Auth flows

`AuthStore` wraps the underlying auth methods and updates observable state for you, including:

- email sign-up and sign-in
- username sign-in and availability checks
- Sign in with Apple
- social sign-in and generic OAuth
- anonymous sign-in and upgrade flows
- magic links
- email OTP
- phone OTP
- two-factor flows
- passkeys
- account management
- linked accounts
- session and device-session management

If you want lower-level control or a non-SwiftUI architecture, use `BetterAuth` directly.
