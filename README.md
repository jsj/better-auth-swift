# better-auth-swift

[![Xcode Cloud Status](https://github.com/jsj/better-auth-swift/actions/workflows/xcode-cloud-status.yml/badge.svg?branch=main)](https://github.com/jsj/better-auth-swift/actions/workflows/xcode-cloud-status.yml)
![Swift 6](https://img.shields.io/badge/Swift-6-orange.svg)
![Platforms](https://img.shields.io/badge/platforms-iOS%2018%2B%20%7C%20macOS%2015%2B-blue.svg)
![SwiftPM](https://img.shields.io/badge/SwiftPM-supported-brightgreen.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Swift SDK for [Better Auth](https://www.better-auth.com/) with first-class support for native Apple apps talking to any Better Auth backend reachable over HTTP.

> [!WARNING]
> This is an early release. The API may change before `1.0`, and the first tagged release will start at `0.0.1`.

> [!NOTE]
> This is an independent community SDK and is not officially affiliated with or maintained by the Better Auth team.

## Why this exists

`better-auth-swift` gives Swift apps a native-feeling auth client for Better Auth:

- secure session persistence
- session restore and refresh flows
- native Apple sign-in payload exchange
- authenticated requests with retry after `401`
- optional SwiftUI state management helpers

## Quick start

### Requirements

- iOS 18+
- macOS 15+
- Xcode 16+
- Swift 6

### Add the package

```swift
dependencies: [
    .package(url: "https://github.com/jsj/better-auth-swift.git", from: "0.0.1")
]
```

Then add the products you want:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift")
    ]
)
```

Use `BetterAuth` if you only want the core SDK. Add `BetterAuthSwiftUI` only if you want the observable `AuthStore` helper for SwiftUI app state.

### Create a client

```swift
import BetterAuth

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!
)
```

### Restore a session at app launch

```swift
let session = try await client.auth.restoreOrRefreshSession()
```

### Make an authenticated request

```swift
struct Profile: Decodable {
    let id: String
    let email: String
}

let profile: Profile = try await client.requests.sendJSON(path: "/api/me")
```

## Choose your path

### Core SDK

Use `BetterAuth` if you want framework-agnostic auth primitives for UIKit, SwiftUI, or your own architecture.

```swift
import BetterAuth

let client = BetterAuthClient(
    configuration: BetterAuthConfiguration(
        baseURL: URL(string: "https://your-api.example.com")!,
        storage: .init(
            key: "better-auth.session",
            service: "com.example.myapp.auth"
        ),
        endpoints: .init(
            socialSignInPath: "/api/auth/social/sign-in",
            nativeAppleSignInPath: "/api/auth/apple/native",
            sessionRefreshPath: "/api/auth/session/refresh",
            currentSessionPath: "/api/auth/session",
            signOutPath: "/api/auth/sign-out"
        ),
        clockSkew: 60
    )
)
```

### SwiftUI state helper

Use `BetterAuthSwiftUI` if you want an observable store for app-layer state.

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

Common actions:

```swift
await authStore.restore()
await authStore.refresh()
await authStore.signOut()
```

State exposed by `AuthStore`:

- `session`
- `isLoading`
- `statusMessage`

## First sign-in example

The SDK includes `AppleNativeSignInPayload` for exchanging native Apple credentials with a Better Auth backend.

> [!IMPORTANT]
> Native Apple Sign In requires [better-auth/better-auth#8870](https://github.com/better-auth/better-auth/pull/8870) to be merged. Without this fix, Apple's hashed nonce in the ID token will fail server-side verification against the raw nonce. If you're running a local or patched better-auth instance this works today; stock releases will need the fix first.

```swift
let payload = AppleNativeSignInPayload(
    token: identityToken,
    nonce: rawNonce,
    authorizationCode: authorizationCode,
    email: email,
    givenName: givenName,
    familyName: familyName
)

let session = try await client.auth.signInWithApple(payload)
```

## Authenticated requests

Send JSON:

```swift
struct UpdateProfileRequest: Encodable {
    let name: String
}

try await client.requests.sendWithoutDecoding(
    path: "/api/profile",
    method: "PATCH",
    body: UpdateProfileRequest(name: "James")
)
```

Call public endpoints without authentication:

```swift
let health: Healthcheck = try await client.requests.sendJSON(
    path: "/api/health",
    requiresAuthentication: false
)
```

## Example apps

For full working examples in this repo:

- [`examples/cf-workers-swiftui`](./examples/cf-workers-swiftui) — SwiftUI app + Cloudflare Workers example backend
- [`examples/cf-workers-uikit`](./examples/cf-workers-uikit) — UIKit app + Cloudflare Workers example backend

## Backend compatibility

This SDK is designed to work with Better Auth backends in general, including deployments on Vercel, Node servers, Cloudflare Workers, or other environments, as long as your Swift app can reach the backend over HTTP.

The core flow looks like this:

- sign in from iPhone, iPad, or Mac
- exchange credentials with a Better Auth backend
- persist the session securely
- refresh tokens when needed
- make authenticated requests from app code

This repo currently includes Cloudflare Workers-based example stacks, but the SDK itself is not coupled to Workers.

## Status

This package is under active development. The current focus is a solid core auth bridge between Better Auth backends and native Swift apps before broadening the API surface further.

## Contributing

Issues and pull requests are welcome.
