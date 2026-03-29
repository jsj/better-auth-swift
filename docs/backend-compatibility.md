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

## Cloudflare Workers in this repo

This repository includes Cloudflare Workers-based example stacks because they are convenient full-stack demos, not because the SDK requires Workers specifically.
