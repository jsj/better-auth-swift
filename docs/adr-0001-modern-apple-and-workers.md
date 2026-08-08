# ADR 0001: Modern Apple Floor and Serverless Self-Hosted Wedge

## Status

Accepted.

## Context

`better-auth-swift` is a native Swift client SDK for Better Auth.
It is not a direct copy of Firebase Auth or Supabase Auth.

Firebase and Supabase provide mature hosted platforms, but they also introduce
vendor lock-in and can cost too much for basic authentication. Better Auth can
run in self-hosted environments, including serverless Cloudflare Workers.
Apple apps can use native authentication without a hosted identity vendor.

The package currently targets iOS 17+, macOS 14+, and Swift 6 mode.

ADR 0002 supersedes this platform list after the package added watchOS,
visionOS, and tvOS support. The modern platform-floor decision remains active.

## Decision

Keep the modern platform floor:

- iOS 17+
- macOS 14+
- Swift 6 mode

Position Cloudflare Workers as the primary reference backend for serverless,
self-hosted Better Auth compatibility. Workers support is not a hard runtime
dependency. The Workers examples in this repository are product surfaces and
contract-test targets, not only sample code.

## Consequences

- The SDK can use strict concurrency, actors, `AsyncStream`, Observation, and
  other modern Swift patterns without completion-handler or Objective-C-era
  compatibility shims.
- The SwiftUI product can lean on `@Observable` instead of maintaining older
  observation layers.
- The SDK must not use Firebase-style global singleton configuration, method
  swizzling, plist magic, and hidden app lifecycle hooks.
- Backend portability must remain explicit. Route catalogs, bearer/session
  semantics, plugin availability, and error mapping must have documentation and
  tested through contract coverage.
- Future requests to lower the platform floor require evaluation as a major
  product tradeoff, not as routine compatibility work.
