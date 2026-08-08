# Project context

## Product focus

`better-auth-swift` is a native Apple client SDK for Better Auth. It supports
self-hosted Better Auth backends. Cloudflare Workers provide the primary serverless reference.

The SDK provides native Apple interfaces, reliable sessions, and backend portability.

## Domain terms

- **Apple client**: An app for iOS, macOS, watchOS, visionOS, or tvOS that uses
  the Swift package products.
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
- **Session outcome**: A result from an Auth flow that core applies to session
  storage and Auth state. Examples include a signed-in session, a token with a
  fallback user, an updated user, or sign-out.
- **Auth operation**: One invocation of an Auth flow from the SwiftUI Adapter.
  Each invocation has independent in-flight, success, failure, and cancellation
  state.
- **Request pipeline**: URL resolution, auth attachment, request hooks, retry
  policy, status validation, decoding, and session refresh retry behavior.
- **Backend contract**: The wire-level behavior the SDK expects from a Better
  Auth backend, including paths, methods, headers, response shapes, and error
  semantics.
- **Backend diagnostics**: Optional backend metadata that reports reachability
  and available Better Auth features before authentication starts.

## Architecture rules

- Prefer modern Swift interfaces over legacy compatibility shims.
- Keep the SDK instance-based and injectable. Do not introduce a global auth
  singleton.
- Make backend compatibility explicit and testable. Diagnostics must identify
  missing server plugins and route mismatches.
- Keep auth behavior in core modules and SwiftUI view state in SwiftUI modules.
- Treat each public API added before `1.0` as a possible long-term promise.
- Reduce or change broad surfaces before you tag `1.0`.
- Use namespaced Auth flows as the canonical public Interface.
- Keep Plugin module session mutation behind the core Session outcome Seam.
- Treat platform support as a compilation and core behavior promise. Do not
  imply that each system authentication user experience exists on every
  platform.
