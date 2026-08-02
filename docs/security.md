# Security Posture

## Token Storage

By default, `better-auth-swift` stores the encoded `BetterAuthSession` in the Apple Keychain through `KeychainSessionStore`.
The session includes access and refresh tokens. Select the most restrictive Keychain options that your app can use:

- Use the default non-synchronizable storage unless cross-device session sync is intentional.
- Use an access group only when sharing auth state across targets is required.
- Prefer stricter Keychain accessibility when background access is not needed.

The SDK does not add an application-level encryption envelope to Keychain storage.
Envelope encryption requires each app to manage an encryption-key lifecycle.
Apps that require an additional envelope can provide a custom `BetterAuthSessionStore`.

## Storage Migration

If an app changes its Keychain storage key, configure `migrationKeys` with the previous keys.
During the next session load, the SDK examines the active key first.
Then it examines each migration key in order.
The SDK copies the first legacy session to the active key and removes the legacy session.

```swift
let client = BetterAuthClient(
    baseURL: authURL,
    storage: .init(
        key: "com.example.auth.session.v2",
        migrationKeys: ["com.example.auth.session.v1"]
    )
)
```

A change to `service`, `accessGroup`, or `synchronizable` changes the Keychain query.
For these changes, provide a custom `BetterAuthSessionStore` that can read the old and new locations.

## Transport Security

`URLSessionTransport` accepts a caller-provided `URLSession`.
Apps can supply a session configuration and delegate for certificate pinning, proxy policy, or enterprise TLS requirements.

## Client-Side Throttling

Client-side throttling is optional and complements server-side rate limits. Enable it with:

```swift
let client = BetterAuthClient(
    baseURL: authURL,
    auth: .init(throttlePolicy: .init(minimumInterval: 1))
)
```

Server-side rate limiting remains required. Client-side throttling prevents accidental repeated requests, but it is not a security boundary.
