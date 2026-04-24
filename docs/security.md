# Security Posture

## Token Storage

By default, `better-auth-swift` stores the encoded `BetterAuthSession` in the Apple Keychain through `KeychainSessionStore`.
The session includes access and refresh tokens, so apps should choose the narrowest viable Keychain options for their threat model:

- Use the default non-synchronizable storage unless cross-device session sync is intentional.
- Use an access group only when sharing auth state across targets is required.
- Prefer stricter Keychain accessibility when background access is not needed.

The SDK does not add an application-level encryption envelope on top of Keychain storage today. That is intentional for the default path because envelope encryption requires app-owned key lifecycle decisions that vary by product. Apps that require an additional envelope can provide a custom `BetterAuthSessionStore`.

## Transport Security

`URLSessionTransport` accepts a caller-provided `URLSession`, so apps can supply their own session configuration and delegate for certificate pinning, proxy policy, or enterprise TLS requirements.

## Client-Side Throttling

Client-side throttling is optional and complements server-side rate limits. Enable it with:

```swift
let client = BetterAuthClient(
    baseURL: authURL,
    auth: .init(throttlePolicy: .init(minimumInterval: 1))
)
```

Server-side rate limiting remains required; client-side throttling is a UX and accidental-hammering guard, not a security boundary.
