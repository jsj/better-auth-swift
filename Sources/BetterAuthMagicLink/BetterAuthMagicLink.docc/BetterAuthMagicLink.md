# ``BetterAuthMagicLink``

Use the Better Auth Magic Link plugin from a Swift application.

## Overview

Add this product only if the backend uses the Better Auth Magic Link plugin.
The module owns Magic Link routes, request models, verification, and incoming URLs.
Core applies successful verification results through the Session outcome Seam.

### Enable the module

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

### Handle an incoming URL

```swift
let result = try await magicLinks.handleIncomingURL(url)
```

The method returns `nil` if the URL does not match the configured scheme and verification route.

## Topics

### Module access

- ``BetterAuthMagicLinkModule``
- ``BetterAuthMagicLinkClient``
- ``BetterAuthMagicLinkEndpoints``

### Requests and results

- ``MagicLinkRequest``
- ``MagicLinkVerifyRequest``
- ``MagicLinkVerificationResult``
- ``MagicLinkFailure``
