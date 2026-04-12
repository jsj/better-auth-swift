<p align="center">
  <img src="./.README/cover.png" alt="A Swift SDK for Better Auth" width="1024" />
</p>

<h1 align="center">better-auth-swift</h1>

<p align="center">
  A Swift SDK for <a href="https://github.com/better-auth/better-auth">Better Auth</a>
</p>

<p align="center">
  <a href="https://github.com/jsj/better-auth-swift/actions/workflows/xcode-cloud-status.yml"><img src="https://github.com/jsj/better-auth-swift/actions/workflows/xcode-cloud-status.yml/badge.svg?branch=main" alt="Xcode Cloud Status" /></a>
  <img src="https://img.shields.io/badge/Swift-6-orange.svg" alt="Swift 6" />
  <img src="https://img.shields.io/badge/platforms-iOS%2018%2B%20%7C%20macOS%2015%2B-blue.svg" alt="Platforms" />
  <img src="https://img.shields.io/badge/SwiftPM-supported-brightgreen.svg" alt="SwiftPM" />
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

Native Swift SDK for [Better Auth](https://github.com/better-auth/better-auth) with first-class support for Apple platforms.

> [!WARNING]
> This is an early release. The API may change before `1.0`, and the first tagged release will start at `0.0.1`.

> [!NOTE]
> This is an independent community SDK and is not officially affiliated with or maintained by the Better Auth team.

## Features

| Category | What's supported |
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
| **Organizations** | Create, list, update, delete orgs; manage members and invitations (plugin module) |
| **SwiftUI** | Observable `AuthStore` with launch state, session, loading |
| **Keychain** | Reinstall-aware session persistence with configurable accessibility |

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

Three products are available:

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
let result = try await client.auth.restoreSessionOnLaunch()
```

### Sign in

```swift
// Email + password
let session = try await client.auth.signInWithEmail(
    EmailSignInRequest(email: "user@example.com", password: "password")
)

// Apple native sign in
let session = try await client.auth.signInWithApple(payload)

// Anonymous (upgrade later)
let session = try await client.auth.signInAnonymously()
```

### Make authenticated requests

```swift
let profile: Profile = try await client.requests.sendJSON(path: "/api/me")
```

The request client automatically attaches bearer tokens and retries once on `401` after refreshing the session.

## SwiftUI integration

```swift
import BetterAuthSwiftUI

@MainActor
let store = AuthStore(client: client)

// Launch
await store.bootstrap()

// Drive UI from typed launch state
switch store.launchState {
case .authenticated(let session): // show app
case .unauthenticated:            // show sign in
case .restoring:                  // show loading
default: break
}
```

## Organization plugin

```swift
import BetterAuthOrganization

let orgs = OrganizationManager(client: client)

let org = try await orgs.createOrganization(
    CreateOrganizationRequest(name: "Acme", slug: "acme")
)
let members = try await orgs.listMembers(organizationId: org.id)
```

## Apple Sign In

> [!NOTE]
> Native Apple Sign In support depends on the Better Auth server version and configuration you are integrating with. Verify compatibility against the backend version you deploy.

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

This SDK works with any Better Auth backend reachable over HTTP — Vercel, Node, Cloudflare Workers, or any other host. The SDK handles session persistence, token refresh, and authenticated requests; the backend handles the auth logic.

## Contributing

Issues and pull requests are welcome.
