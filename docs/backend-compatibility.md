# Backend Compatibility

This SDK is not tied to Cloudflare Workers.

It is designed to work with Better Auth backends in general, as long as your Swift app can reach the backend over HTTP and the backend exposes the routes expected by the SDK.

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

If your backend uses custom route paths, configure them with `BetterAuthConfiguration.Endpoints`.

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

This repository includes Cloudflare Workers-based example stacks because they are convenient full-stack demos, not because the SDK requires Workers specifically.
