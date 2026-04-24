# Client Configuration

`BetterAuthClient` can be created from a full `BetterAuthConfiguration` or from the convenience `baseURL` initializer.

## Minimal setup

```swift
import BetterAuth

let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!
)
```

## Full configuration

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
            socialSignInPath: "/api/auth/sign-in/social",
            nativeAppleSignInPath: "/api/auth/apple/native",
            sessionRefreshPath: "/api/auth/get-session",
            currentSessionPath: "/api/auth/get-session",
            signOutPath: "/api/auth/sign-out"
        ),
        clockSkew: 60,
        autoRefreshToken: true,
        callbackURLSchemes: ["yourapp"],
        retryPolicy: .default,
        logger: nil
    )
)
```

## What you can customize

### `baseURL`

The root URL for your Better Auth backend.

### `storage`

Controls how sessions are stored locally.

- `key`: storage key used for the session payload
- `service`: keychain service name
- `accessGroup`: optional shared keychain group
- `accessibility`: keychain accessibility level
- `synchronizable`: whether the keychain item is synchronizable

Use `BetterAuthConfiguration.SessionStorage.shared(...)` when sharing credentials across app targets with an access group.

### `endpoints`

Override endpoint paths if your Better Auth deployment uses custom routing. The default configuration covers the routes expected by this SDK's current contract surface.

For Apple sign-in, `nativeAppleSignInPath` is the SDK's native Apple bridge endpoint, while `socialSignInPath` is the general social sign-in route used by broader OAuth-style flows.

### `clockSkew`

Controls how aggressively the SDK treats access tokens as nearing expiry.

### `autoRefreshToken`

When enabled, restoring a session starts automatic refresh behavior inside the session manager.

### `callbackURLSchemes`

Allowed custom URL schemes for incoming auth callbacks. The SDK always accepts the configured backend `baseURL` scheme; add your app scheme here when you use deep links such as `yourapp://oauth/success`.

### `retryPolicy`

Used by the internal network layer for retry behavior.

### `logger`

Optional logger for debugging SDK behavior.
