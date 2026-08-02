<p align="center">
  <img src="./.README/cover.png" alt="A Swift SDK for Better Auth" width="1024" />
</p>

<h1 align="center">better-auth-swift</h1>

<p align="center">
  A Swift SDK for <a href="https://github.com/better-auth/better-auth">Better Auth</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Swift-6-orange.svg" alt="Swift 6" />
  <img src="https://img.shields.io/badge/platforms-iOS%2017%2B%20%7C%20macOS%2014%2B-blue.svg" alt="Platforms" />
  <img src="https://img.shields.io/badge/SwiftPM-supported-brightgreen.svg" alt="SwiftPM" />
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

This native Swift SDK supports [Better Auth](https://github.com/better-auth/better-auth) on Apple platforms.

You can use a self-hosted Better Auth backend. This includes serverless Cloudflare Workers deployments.
You do not have to use Firebase or Supabase for authentication.

> [!WARNING]
> This is an early release. The API can change before `1.0`. The first tagged release will be `0.0.1`.

> [!NOTE]
> The Better Auth team does not maintain or officially support this independent community SDK.

## Features

| Category | Supported features |
|----------|-----------------|
| **Email + Password** | Sign up, sign in, password reset, password change |
| **Username** | Username sign in, availability check |
| **Apple Sign In** | Native credential exchange (no web redirect) |
| **Social / OAuth** | Social sign in, generic OAuth initiation + completion |
| **Anonymous** | Anonymous sign in, upgrade to permanent account |
| **Magic Link** | Request and verify magic links |
| **Email OTP** | Request, sign in, and verify email OTP codes |
| **Phone OTP** | Request, sign in, and verify phone OTP codes |
| **Passkeys** | Register, authenticate, list, update, delete |
| **Two-Factor** | Enable, disable, TOTP verify, OTP verify, backup codes |
| **Session Management** | List, revoke current/other/all, device sessions, JWT/JWKS |
| **Account Lifecycle** | Delete account, re-authenticate, change email, update profile |
| **Account Linking** | Link social accounts, list linked accounts |
| **Organizations** | Create, list, update, and delete organizations. Manage members and invitations (plugin module). |
| **SwiftUI** | Observable `AuthStore` with launch state, session, loading |
| **Keychain** | Reinstall-aware session persistence with configurable accessibility |

## Quick start

### Requirements

- iOS 17+
- macOS 14+
- Xcode 16+
- Swift 6

### Add the package

Add the package in Xcode. Use this repository URL:

```text
https://github.com/jsj/better-auth-swift.git
```

Alternatively, add the package to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/jsj/better-auth-swift.git")
]
```

The package provides three products:

| Product | Use case |
|---------|----------|
| `BetterAuth` | Core SDK — session, auth flows, authenticated requests |
| `BetterAuthSwiftUI` | Observable `AuthStore` for SwiftUI apps |
| `BetterAuthOrganization` | Organization plugin — teams, members, invitations |

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift"),
        .product(name: "BetterAuthOrganization", package: "better-auth-swift")
    ]
)
```

### Create a client

```swift
import BetterAuth

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!
)
```

### Restore a session at app launch

```swift
let result = try await client.auth.lifecycle.restoreOnLaunch()

switch result {
case .noStoredSession:
    // Show signed-out UI.
case .restored(let session, _, _):
    // Show signed-in UI.
case .cleared:
    // Stored session was invalid and local state was cleared.
}
```

### Sign in

```swift
// Email + password
let session = try await client.auth.email.signIn(
    EmailSignInRequest(email: "user@example.com", password: "password")
)

// Apple native sign in
let session = try await client.auth.apple.signIn(payload)

// Anonymous (upgrade later)
let session = try await client.auth.anonymous.signIn()
```

### Make authenticated requests

```swift
let profile: Profile = try await client.requests.sendJSON(path: "/api/me")
```

The request client attaches bearer tokens. It uses the configured transient retry policy.
After a `401` response, it refreshes the session and retries once.

### Make sure that the backend is compatible

```swift
let report = await client.diagnostics.check(
    expectedFeatures: [.bearer, .emailPassword, .passkey]
)
```

The Cloudflare Workers examples expose `/api/better-auth-swift/diagnostics`.
Apps can use this endpoint to make sure that the backend supports the required plugins.

## SwiftUI integration

```swift
import BetterAuthSwiftUI

@MainActor
let store = AuthStore(client: client)

// Launch
await store.lifecycle.bootstrap()

// Drive UI from typed launch state
switch store.viewState.launchState {
case .authenticated(let session):
    print("Show app", session.user.id)
case .unauthenticated:
    print("Show sign in")
case .restoring:
    print("Show loading")
default:
    break
}

// Namespaced UI actions keep view code organized
await store.email.signIn(.init(email: email, password: password))
await store.lifecycle.signOut()
```

## Organization plugin

```swift
import BetterAuthOrganization

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!,
    modules: [BetterAuthOrganizationModule()]
)

guard let orgs = client.organizationModule?.manager else {
    throw BetterAuthError.invalidResponse
}

let org = try await orgs.createOrganization(
    CreateOrganizationRequest(name: "Acme", slug: "acme")
)
let members = try await orgs.listMembers(organizationId: org.id)
```

If the backend uses a different path for organization routes, register the module with a route catalog:

```swift
let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!,
    modules: [
        BetterAuthOrganizationModule(
            endpoints: .init(listPath: "/custom/auth/organization/list")
        )
    ]
)
```

## Apple Sign In

> [!NOTE]
> Native Apple Sign In support depends on the deployed Better Auth version and configuration.

Make sure that the deployed backend supports Native Apple Sign In.

```swift
let session = try await client.auth.signInWithApple(
    AppleNativeSignInPayload(
        token: identityToken,
        nonce: rawNonce,
        authorizationCode: authorizationCode,
        email: email,
        givenName: givenName,
        familyName: familyName
    )
)
```

## Example apps

- [`examples/cf-workers-swiftui`](./examples/cf-workers-swiftui) — SwiftUI app + Cloudflare Workers backend
- [`examples/cf-workers-uikit`](./examples/cf-workers-uikit) — UIKit app + Cloudflare Workers backend

## Backend compatibility

This SDK works with Better Auth backends that are available through HTTP.
Supported hosts include Vercel, Node, and Cloudflare Workers.
The SDK manages sessions, token refresh, and authenticated requests.
The backend manages authentication.

## Contributing

Issues and pull requests are welcome.
