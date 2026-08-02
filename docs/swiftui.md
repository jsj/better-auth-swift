# SwiftUI

If you want an observable wrapper around the core SDK, use `BetterAuthSwiftUI`.

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
- `viewState`
- `lastRestoreResult`
- `isLoading`
- `statusMessage`
- `lastError`
- `lastUnderlyingError`

## App launch

```swift
await authStore.lifecycle.bootstrap()

switch authStore.viewState.launchState {
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
    Task { await authStore.oauth.handleIncomingURL(url) }
}
```

## Common lifecycle calls

```swift
await authStore.lifecycle.bootstrap()
await authStore.lifecycle.restore()
await authStore.lifecycle.refresh()
await authStore.lifecycle.fetchCurrentSession()
await authStore.lifecycle.signOut()
authStore.lifecycle.shutdown()
```

## Auth flows

`AuthStore` wraps the underlying authentication methods and updates observable state.
Use the namespaced API for new UI code:

```swift
await authStore.email.signIn(.init(email: email, password: password))
await authStore.magicLinks.request(.init(email: email))
let passkeys = try await authStore.passkeys.list()
let sessions = try await authStore.sessions.list()
```

Available namespaces:

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
