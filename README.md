<p align="center">
  <img src="./.README/cover.png" alt="A Swift SDK for Better Auth" width="1024" />
</p>

<h1 align="center">better-auth-swift</h1>

<p align="center">
  A Swift SDK for <a href="https://github.com/better-auth/better-auth">Better Auth</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Swift-6-orange.svg" alt="Swift 6" />
  <img src="https://img.shields.io/badge/platforms-iOS%2017%2B%20%7C%20macOS%2014%2B%20%7C%20watchOS%2010%2B%20%7C%20visionOS%201%2B%20%7C%20tvOS%2017%2B-blue.svg" alt="Platforms" />
  <img src="https://img.shields.io/badge/SwiftPM-supported-brightgreen.svg" alt="SwiftPM" />
  <a href="https://swiftpackageindex.com/jsj/better-auth-swift/documentation"><img src="https://img.shields.io/badge/DocC-hosted-blue.svg" alt="Hosted DocC documentation" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" /></a>
</p>

<details open>
<summary align="center"><img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/claude.svg" width="18" height="18" alt="Claude">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/cursor.svg" width="18" height="18" alt="Cursor">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/github-copilot.svg" width="18" height="18" alt="GitHub Copilot">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/openai.svg" width="18" height="18" alt="OpenAI">&nbsp;&nbsp;<strong>Copy this prompt to your coding agent</strong></summary>

```text
Use Better Auth from iOS, macOS, watchOS, visionOS, or tvOS.

Before you change files, inspect these parts of the repository:
- The current authentication flow
- The backend configuration
- The session model and storage
- The package management method
- The related tests

Then describe the smallest integration plan.

Add https://github.com/jsj/better-auth-swift.git with the existing Swift package method and version style.
Use the SDK README, documentation, and examples as the source of truth.
If you need more details, clone the SDK outside the app repository:

gh repo clone jsj/better-auth-swift <temporary-directory>

Keep the app's public authentication interface unless a change is necessary.
Put BetterAuthClient behind the current authentication interface.
Map the app session model to the Better Auth session model in one location.

Add only the authentication flows that the app uses.
Configure the backend base URL.
Configure other values only when a flow requires them.
These values can include the callback URL scheme, request origin, transport, and session storage.

Use the app's current configuration and secret-management methods.
Do not add production credentials.
Do not put secrets in source files.
Do not change the production backend configuration.
Use synthetic users and fixtures that contain no personally identifiable information.

Add or update one focused authentication test.
Use a mock or local transport unless the repository has a live-test command.
Run the smallest related test command.
Run the smallest related build command.

If the backend lacks a required route or plugin, finish all safe client work.
Report the blocked behavior and the backend requirement.
Do not create an incompatible client workaround.

Report these results:
- Changed files
- Added package products and version rule
- Added authentication flows
- Test and build commands
- Test and build results
- Backend requirements and compatibility gaps
```

</details>

## Features

| Category | Supported features |
|----------|-----------------|
| **Email + Password** | Sign up, sign in, password reset, reauthentication (optional module) |
| **Username** | Username sign in and availability check (optional module) |
| **Apple Sign In** | Native credential exchange with no web redirect (optional module) |
| **Social / OAuth** | Social sign in, generic OAuth, and account linking (optional module) |
| **Anonymous** | Anonymous sign in and deletion (optional module) |
| **Magic Link** | Request and verify magic links (optional plugin module) |
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
- watchOS 10+
- visionOS 1+
- tvOS 17+
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
    .package(url: "https://github.com/jsj/better-auth-swift.git", branch: "main")
]
```

The package provides a small core plus optional products:

| Product | Use case |
|---------|----------|
| `BetterAuth` | Core SDK — sessions, account lifecycle, OTP, passkeys, and authenticated requests |
| `BetterAuthEmailPassword` | Email sign-up, sign-in, password reset, and reauthentication |
| `BetterAuthUsername` | Username availability and sign-in |
| `BetterAuthAnonymous` | Anonymous sign-in and deletion |
| `BetterAuthSocialOAuth` | Social providers, generic OAuth, and account linking |
| `BetterAuthAppleSignIn` | Native Sign in with Apple credential exchange |
| `BetterAuthMagicLink` | Magic Link plugin — requests, verification, incoming URLs |
| `BetterAuthSwiftUI` | Observable `AuthStore` for SwiftUI apps |
| `BetterAuthOrganization` | Organization plugin — members, roles, invitations |

### Magic Link plugin

Add `BetterAuthMagicLink` only if the backend uses the Better Auth Magic Link plugin.

```swift
import BetterAuth
import BetterAuthMagicLink

let client = BetterAuthClient(
    configuration: BetterAuthConfiguration(
        baseURL: URL(string: "https://auth.example.com")!,
        callbackURLSchemes: ["your-app"]
    ),
    modules: [BetterAuthMagicLinkModule()]
)

let magicLinks = try client.requireMagicLinks()
try await magicLinks.request(.init(email: "person@example.com"))
```

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "BetterAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthEmailPassword", package: "better-auth-swift"),
        .product(name: "BetterAuthUsername", package: "better-auth-swift"),
        .product(name: "BetterAuthAnonymous", package: "better-auth-swift"),
        .product(name: "BetterAuthSocialOAuth", package: "better-auth-swift"),
        .product(name: "BetterAuthAppleSignIn", package: "better-auth-swift"),
        .product(name: "BetterAuthMagicLink", package: "better-auth-swift"),
        .product(name: "BetterAuthSwiftUI", package: "better-auth-swift"),
        .product(name: "BetterAuthOrganization", package: "better-auth-swift")
    ]
)
```

### Create a client

```swift
import BetterAuth
import BetterAuthAnonymous
import BetterAuthAppleSignIn
import BetterAuthEmailPassword
import BetterAuthSocialOAuth
import BetterAuthUsername

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!,
    modules: [
        BetterAuthEmailPasswordModule(),
        BetterAuthUsernameModule(),
        BetterAuthAnonymousModule(),
        BetterAuthSocialOAuthModule(),
        BetterAuthAppleSignInModule()
    ]
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
let session = try await client.requireEmailPassword().signIn(
    EmailSignInRequest(email: "user@example.com", password: "password")
)

// Apple native sign in
let session = try await client.requireAppleSignIn().signIn(payload)

// Anonymous (upgrade later)
let session = try await client.requireAnonymous().signIn()
```

### Make authenticated requests

```swift
let profile: Profile = try await client.requests.sendJSON(path: "/api/me")
```

The request client attaches bearer tokens. GET, HEAD, and OPTIONS requests use the
configured transient retry policy by default. Mutations require an explicit
`allowsTransientRetry: true` and should opt in only when repeating the operation is safe.
Set `allowsTransientRetry: false` for GET endpoints that consume one-time tokens.
After a `401` response, it refreshes the session and retries once.

### Make sure that the backend is compatible

```swift
let report = await client.diagnostics.check(
    expectedFeatures: [.bearer, .emailPassword, .passkey]
)
```

Email/password defaults use Better Auth's standard `/api/auth/sign-up/email`,
`/api/auth/sign-in/email`, and `/api/auth/request-password-reset` routes. Enable
the server's `bearer()` plugin for native session requests. The upstream contract
suite exercises these routes against Better Auth 1.7.1 without example adapters.
A sign-up response with `token: null` succeeds without signing in; its
`requiresVerification` value is `nil` when the server does not supply that information.

The Cloudflare Workers examples expose `/api/better-auth-swift/diagnostics`.
Apps can use this endpoint to make sure that the backend supports the required plugins.

## SwiftUI integration

<!-- swiftui-quick-start -->
```swift
import BetterAuth
import BetterAuthEmailPassword
import BetterAuthSwiftUI

@MainActor
func signInExample(client: BetterAuthClient, email: String, password: String) async {
    let store = AuthStore(client: client)
    await store.lifecycle.bootstrap()

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

    // The client must register BetterAuthEmailPasswordModule.
    await store.perform {
        _ = try await client.requireEmailPassword().signIn(
            .init(email: email, password: password)
        )
    }
    await store.lifecycle.signOut()
}
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

### Local and remote sign-out

Sign-out clears the local session before contacting the server. If remote revocation
fails, the call throws while the app stays signed out locally. Use
`client.auth.lifecycle.signOut(remotely: false)` when only local sign-out is needed.

## Apple Sign In

```swift
let session = try await client.requireAppleSignIn().signIn(
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

## Contributing

[Report a bug](https://github.com/jsj/better-auth-swift/issues/new?template=bug_report.yml) or open a pull request.

<hr>

<h3 align="center">Start now</h3>

<details>
<summary align="center"><img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/claude.svg" width="18" height="18" alt="Claude">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/cursor.svg" width="18" height="18" alt="Cursor">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/github-copilot.svg" width="18" height="18" alt="GitHub Copilot">&nbsp;<img src="https://cdn.jsdelivr.net/gh/jsj/agent-icons@ec84fc0fc6f70311a33800a53121c8cac0e5b48b/openai.svg" width="18" height="18" alt="OpenAI">&nbsp;&nbsp;<strong>Copy this prompt to your coding agent</strong></summary>

```text
Use Better Auth from iOS, macOS, watchOS, visionOS, or tvOS.

Before you change files, inspect these parts of the repository:
- The current authentication flow
- The backend configuration
- The session model and storage
- The package management method
- The related tests

Then describe the smallest integration plan.

Add https://github.com/jsj/better-auth-swift.git with the existing Swift package method and version style.
Use the SDK README, documentation, and examples as the source of truth.
If you need more details, clone the SDK outside the app repository:

gh repo clone jsj/better-auth-swift <temporary-directory>

Keep the app's public authentication interface unless a change is necessary.
Put BetterAuthClient behind the current authentication interface.
Map the app session model to the Better Auth session model in one location.

Add only the authentication flows that the app uses.
Configure the backend base URL.
Configure other values only when a flow requires them.
These values can include the callback URL scheme, request origin, transport, and session storage.

Use the app's current configuration and secret-management methods.
Do not add production credentials.
Do not put secrets in source files.
Do not change the production backend configuration.
Use synthetic users and fixtures that contain no personally identifiable information.

Add or update one focused authentication test.
Use a mock or local transport unless the repository has a live-test command.
Run the smallest related test command.
Run the smallest related build command.

If the backend lacks a required route or plugin, finish all safe client work.
Report the blocked behavior and the backend requirement.
Do not create an incompatible client workaround.

Report these results:
- Changed files
- Added package products and version rule
- Added authentication flows
- Test and build commands
- Test and build results
- Backend requirements and compatibility gaps
```

</details>

## License

[MIT](./LICENSE)

---

<p align="center"><sub>This is an independent community project. The Better Auth team does not maintain or officially support it.</sub></p>
