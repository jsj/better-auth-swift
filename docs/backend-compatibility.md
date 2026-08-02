# Backend Compatibility

This SDK is not tied to Cloudflare Workers.

The SDK works with a Better Auth backend if two conditions are true.
The Swift app must reach the backend through HTTP. The backend must expose the routes that the SDK expects.

Cloudflare Workers are the primary reference backend in this repository because
they provide a concrete self-hosted, serverless example. The Apple SDK does not
require Firebase Auth or Supabase Auth. The backend remains portable.

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

During development or onboarding, use `client.diagnostics.check(...)` to examine
the configured backend. The report shows reachability and the available features:

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

The metadata endpoint is optional for generic Better Auth deployments.
For self-hosted apps, the endpoint reports plugin and route mismatches.

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

Enable an optional test only if the backend has the related Better Auth feature.

## Cloudflare Workers in this repo

This repository includes Cloudflare Workers-based example stacks because they
are the reference path for serverless Better Auth deployments. They must remain
aligned with the SDK backend contract and serve as contract-test targets
for supported auth flows.
