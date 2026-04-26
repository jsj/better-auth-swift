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

let configuration = BetterAuthConfiguration(
    baseURL: URL(string: "https://your-api.example.com")!,
    storage: .shared(
        service: "com.example.myapp.auth",
        accessGroup: "ABCDE12345.com.example.shared"
    ),
    endpoints: .init(
        auth: .init(
            socialSignInPath: "/api/auth/sign-in/social",
            nativeAppleSignInPath: "/api/auth/apple/native"
        ),
        session: .init(
            sessionRefreshPath: "/api/auth/get-session",
            currentSessionPath: "/api/auth/get-session",
            signOutPath: "/api/auth/sign-out"
        )
    ),
    auth: .init(
        clockSkew: 60,
        autoRefreshToken: true,
        callbackURLSchemes: ["yourapp"]
    ),
    networking: .init(
        retryPolicy: .default,
        requestOrigin: "https://your-api.example.com",
        timeoutInterval: 15
    ),
    logger: nil
)

let client = BetterAuthClient(configuration: configuration)
```

The convenience initializer accepts the same configuration pieces directly:

```swift
let client = BetterAuthClient(
    baseURL: URL(string: "https://your-api.example.com")!,
    callbackURLSchemes: ["yourapp"],
    requestOrigin: "https://your-api.example.com"
)
```

## What you can customize

### `baseURL`

The root URL for your Better Auth backend.

### `storage`

Controls how sessions are stored locally.

- `key`: storage key used for the session payload
- `service`: Keychain service name
- `accessGroup`: optional shared Keychain group
- `accessibility`: Keychain accessibility level
- `synchronizable`: whether the Keychain item is synchronizable

Use `BetterAuthConfiguration.SessionStorage.shared(...)` when sharing credentials across app targets with an access group.

### `endpoints`

Override endpoint paths if your Better Auth deployment uses custom routing. Endpoints are grouped by feature: `auth`, `user`, `session`, `oauth`, `passkey`, `magicLink`, `emailOTP`, `phoneOTP`, and `twoFactor`.

### `auth`

Controls auth-specific behavior:

- `clockSkew`: how aggressively the SDK treats access tokens as nearing expiry
- `autoRefreshToken`: whether restored sessions start automatic refresh behavior
- `throttlePolicy`: optional minimum interval between repeated auth operations
- `callbackURLSchemes`: allowed custom URL schemes for incoming auth callbacks

### `networking`

Controls request behavior:

- `retryPolicy`: retry behavior for transient networking failures
- `requestOrigin`: optional `Origin` header override
- `timeoutInterval`: URL request timeout

### `logger`

Optional logger for SDK diagnostics. The SDK includes `OSLogBetterAuthLogger` and `PrintBetterAuthLogger`.
