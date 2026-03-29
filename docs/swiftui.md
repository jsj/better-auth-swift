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
- `isLoading`
- `statusMessage`

## Common lifecycle calls

```swift
await authStore.restore()
await authStore.refresh()
await authStore.fetchCurrentSession()
await authStore.signOut()
```

## Auth flows

`AuthStore` wraps many of the underlying auth methods and updates state for you, including:

- email sign-up and sign-in
- username sign-in
- Sign in with Apple
- social sign-in
- anonymous sign-in
- magic links
- email OTP
- phone OTP
- two-factor flows
- passkeys
- account management
- session management helpers

If you want lower-level control or a non-SwiftUI architecture, use `BetterAuth` directly instead.
