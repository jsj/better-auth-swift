# ``BetterAuth``

Use Better Auth from iOS, macOS, watchOS, visionOS, or tvOS.

## Overview

BetterAuth provides typed requests for Better Auth servers. It also stores sessions and refreshes access tokens.

The library supports password, social, one-time-code, passkey, two-factor, and account-management flows.

### Create a client

Create one client for the application. Set the URL of your Better Auth server.

```swift
import BetterAuth

let client = BetterAuthClient(
    configuration: BetterAuthConfiguration(
        baseURL: URL(string: "https://auth.example.com")!
    )
)
```

### Restore a session

Restore the stored session when the application starts.

```swift
let session = try await client.auth.lifecycle.restoreOrRefresh()
```

### Sign in with email

Send the email address and password to the server.

```swift
let session = try await client.auth.email.signIn(
    EmailSignInRequest(
        email: "person@example.com",
        password: "correct-horse-battery-staple"
    )
)
```

## Topics

### Client

- ``BetterAuthClient``
- ``BetterAuthConfiguration``

### Sessions

- ``BetterAuthSession``
- ``BetterAuthSessionStore``
- ``KeychainSessionStore``

### Authentication

- ``EmailSignInRequest``
- ``SocialSignInRequest``
- ``SocialSignInResult``
- ``AppleSignInSupport``
