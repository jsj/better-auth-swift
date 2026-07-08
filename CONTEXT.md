# Project Context

## Product Wedge

`better-auth-swift` is a first-class Apple client SDK for Better Auth. Its
strategic wedge is native Swift auth against a self-hosted Better Auth backend,
with Cloudflare Workers as the primary serverless reference path.

The SDK should compete with Firebase Auth and Supabase Auth on Apple ergonomics,
session reliability, and portability rather than on vendor-owned backend lock-in.

## Domain Terms

- **Apple client**: An iOS or macOS app using the Swift package products.
- **Better Auth backend**: Any HTTP-reachable Better Auth deployment that exposes
  routes compatible with the SDK's configured endpoint catalog.
- **Cloudflare Workers reference backend**: The example Better Auth deployment
  in this repository. It is both a demo and a contract target for serverless,
  self-hosted compatibility.
- **Session lifecycle**: Restore, refresh, auto-refresh, fetch current session,
  sign out, clear invalid sessions, and publish auth state changes.
- **Auth flow**: A user-facing authentication capability such as email/password,
  username, Apple native sign-in, social OAuth, magic link, OTP, phone auth,
  passkeys, anonymous auth, or two-factor auth.
- **Plugin module**: A Swift package product or runtime module that maps a
  Better Auth server plugin into a typed Swift client surface.
- **Request pipeline**: URL resolution, auth attachment, request hooks, retry
  policy, status validation, decoding, and session refresh retry behavior.
- **Backend contract**: The wire-level behavior the SDK expects from a Better
  Auth backend, including paths, methods, headers, response shapes, and error
  semantics.
- **Backend diagnostics**: Optional backend metadata that lets the Apple client
  verify reachability and advertised Better Auth features before auth flows run.

## Architecture Preferences

- Prefer modern Swift interfaces over legacy compatibility shims.
- Keep the SDK instance-based and injectable. Do not introduce a global auth
  singleton.
- Make backend compatibility explicit and testable. Runtime failures caused by
  missing server plugins or route mismatches should become diagnosable.
- Keep auth behavior in core modules and SwiftUI view state in SwiftUI modules.
- Treat public API added before `1.0` as a candidate long-term compatibility
  promise; shrink or reshape broad surfaces before tagging `1.0`.
