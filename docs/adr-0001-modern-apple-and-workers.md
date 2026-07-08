# ADR 0001: Modern Apple Floor and Serverless Self-Hosted Wedge

## Status

Accepted.

## Context

`better-auth-swift` is intended to be a first-class Swift client SDK for Better
Auth, not a direct clone of Firebase Auth or Supabase Auth.

Firebase and Supabase provide mature hosted platforms, but they also introduce
vendor lock-in and can become cost-prohibitive for basic auth. Better Auth can
run in self-hosted environments, including serverless Cloudflare Workers. This
creates a product wedge for Apple apps that want native auth ergonomics without
committing auth state and billing to a hosted identity vendor.

The package currently targets iOS 17+, macOS 14+, and Swift 6 mode.

## Decision

Keep the modern platform floor:

- iOS 17+
- macOS 14+
- Swift 6 mode

Position Cloudflare Workers as the primary reference backend for serverless,
self-hosted Better Auth compatibility. Workers support is not a hard runtime
dependency, but the repository's Workers examples should be treated as product
surface and contract coverage, not just sample code.

## Consequences

- The SDK can use strict concurrency, actors, `AsyncStream`, Observation, and
  other modern Swift patterns without completion-handler or Objective-C-era
  compatibility shims.
- The SwiftUI product can lean on `@Observable` instead of maintaining older
  observation layers.
- The SDK should avoid Firebase-style global singleton configuration, method
  swizzling, plist magic, and hidden app lifecycle hooks.
- Backend portability must remain explicit. Route catalogs, bearer/session
  semantics, plugin availability, and error mapping should be documented and
  tested through contract coverage.
- Future requests to lower the platform floor should be evaluated as a major
  product tradeoff, not as routine compatibility work.
