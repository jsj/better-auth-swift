# Backend Compatibility

This SDK is not tied to Cloudflare Workers.

It is designed to work with Better Auth backends in general, as long as your Swift app can reach the backend over HTTP and the backend exposes the routes expected by the SDK.

Cloudflare Workers are the primary reference backend in this repository because
they make the self-hosted, serverless path concrete. The intended value
proposition is a native Apple auth SDK without Firebase or Supabase auth
lock-in, while still keeping backend deployment cheap and portable.

## Compatible deployment styles

Typical deployment environments include:

- Vercel
- Node servers
- Cloudflare Workers
- other Better Auth-compatible HTTP backends

## What the SDK expects

The SDK expects:

- a reachable base URL
- Better Auth-compatible auth routes
- session and token semantics compatible with the SDK models
- enabled Better Auth plugins for the client features your app calls

If your backend uses custom route paths, configure them with `BetterAuthConfiguration.Endpoints`.

## Runtime diagnostics

Use `client.diagnostics.check(...)` during development or onboarding to verify
that the configured backend is reachable and advertises the features your app
plans to call:

```swift
let report = await client.diagnostics.check(
    expectedFeatures: [.bearer, .emailPassword, .passkey]
)

if !report.isCompatible {
    print("Missing features", report.missingFeatures)
}
```

The diagnostics client checks:

- `GET /health` by default
- `GET /api/better-auth-swift/diagnostics` by default, when the backend exposes it

The metadata endpoint is optional for generic Better Auth deployments, but it is
recommended for self-hosted apps because it turns plugin and route mismatches
into an explicit compatibility report.

The response shape is:

```json
{
  "ok": true,
  "name": "better-auth-swift-cloudflare-worker",
  "platform": "cloudflare-workers",
  "authBasePath": "/api/auth",
  "features": ["bearer", "email-password", "passkey"],
  "routes": {
    "health": "/health",
    "diagnostics": "/api/better-auth-swift/diagnostics"
  }
}
```

For bearer-token mobile clients, the default session refresh contract is:

- When a refresh token is present, refresh through `sessionRefreshPath` with a
  `POST` body containing the refresh token.
- When no refresh token is present, fetch the current session through
  `currentSessionPath` with `GET` and an `Authorization: Bearer <token>` header.
- Authenticated and unauthenticated app requests use the configured
  `RetryPolicy` for transient transport failures and retryable HTTP statuses.
- Authenticated app requests retry once after a `401` by refreshing the current
  session and rebuilding the request with the new access token.

## Contract test coverage

The release contract suite is intentionally split into required core coverage and optional feature coverage.

| Area | Test | Required configuration |
| ---- | ---- | ---------------------- |
| Email + password session lifecycle | Sign in, fetch current session, refresh if needed, make an authenticated request through `client.requests`, list sessions, and remotely sign out | `BETTER_AUTH_CONTRACT_BASE_URL`, `BETTER_AUTH_CONTRACT_EMAIL`, `BETTER_AUTH_CONTRACT_PASSWORD` |
| Username sign in | Sign in with username, fetch current session, and remotely sign out | `BETTER_AUTH_CONTRACT_BASE_URL`, `BETTER_AUTH_CONTRACT_USERNAME`, `BETTER_AUTH_CONTRACT_USERNAME_PASSWORD` |
| JWKS | Fetch JWKS and require at least one key | `BETTER_AUTH_CONTRACT_BASE_URL`, `BETTER_AUTH_CONTRACT_EXPECT_JWKS=true` |
| Anonymous auth | Sign in anonymously and delete the anonymous user | `BETTER_AUTH_CONTRACT_BASE_URL`, `BETTER_AUTH_CONTRACT_SUPPORTS_ANONYMOUS=true` |

Optional tests should only be enabled for backends that have the corresponding Better Auth feature configured.

## Cloudflare Workers in this repo

This repository includes Cloudflare Workers-based example stacks because they
are the reference path for serverless Better Auth deployments. They should be
kept aligned with the SDK's backend contract and used as contract-test targets
for supported auth flows.
