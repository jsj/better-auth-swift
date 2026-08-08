# ADR 0002: Modular Auth Interfaces and Apple Platform Support

## Status

Accepted.

## Context

The SDK exposes most Auth flows through both flat methods and namespaced
clients. The SwiftUI product repeats both forms. This creates a broad public
Interface before `1.0` and makes the same behavior visible through several
shallow Modules.

The package also defines a Plugin module Interface, but most Better Auth server
plugins still compile into the core product. External Plugin modules can send
requests, but they cannot apply session outcomes through a narrow,
actor-isolated Seam.

The package now compiles for iOS, macOS, watchOS, visionOS, and tvOS. ADR 0001
only records the original iOS and macOS platform floor.

## Decision

### Canonical Auth Interface

Use namespaced Auth flows as the canonical public Interface. Examples include:

- `client.auth.lifecycle.restoreOnLaunch()`
- `client.auth.email.signIn(...)`
- `client.auth.apple.signIn(...)`
- `client.auth.sessions.list()`

Remove duplicate flat Auth methods before `1.0` after repository call sites
move to the namespaced Interface.

The SwiftUI product provides one namespaced Adapter that adds observable view
state. It does not expose a second flat copy of the core Interface.

### Plugin modules

Keep these capabilities in the core `BetterAuth` product:

- Session lifecycle and persistence
- Email and password authentication
- Authenticated requests
- Shared coding, errors, configuration, and Backend diagnostics

Move Better Auth server-plugin-specific Auth flows into optional package
products and runtime Plugin modules. Products follow real server-plugin
boundaries. Do not create a product for each endpoint or helper.

Core provides Plugin modules with a narrow, `Sendable`, actor-isolated Seam for
applying session outcomes. Plugin modules must not mutate session storage or
publish Auth state directly.

Plugin registration rejects duplicate identifiers. Imported Plugin modules use
typed access. Missing registration produces a clear error instead of requiring
string lookup or optional chaining at every call site.

### Request pipeline

Use one deep Request pipeline Implementation for URL resolution, encoding,
transport retry, status validation, decoding, and error parsing. Keep separate
Adapters for Auth routes, raw application requests, decoded application
requests, request hooks, and the single refresh-and-replay policy after `401`.

Retry behavior must account for HTTP method replay safety. Refactoring the
pipeline must preserve existing raw-response and refresh-retry behavior.

### SwiftUI operation state

Track each AuthStore operation with an identifier and an invocation token.
Derive `isLoading` from in-flight operations. Record failure by operation.

App-triggered operations record observable failure state and rethrow. Task
cancellation removes in-flight state without becoming a user-visible Auth
error.

### Apple platform support

The package supports these deployment floors:

- iOS 17+
- macOS 14+
- watchOS 10+
- visionOS 1+
- tvOS 17+

"Supported" means every public package product compiles for the platform and
core HTTP/session behavior is available. It does not mean every platform offers
the same system authentication user experience. Documentation must identify
platform-specific system framework limitations.

Each supported platform requires a remote or local compilation gate. A release
must not rely only on the host macOS build.

This decision supersedes only the platform list in ADR 0001. The modern
platform-floor and serverless self-hosted decisions remain accepted.

## Consequences

- The pre-`1.0` migration intentionally breaks duplicate public surfaces.
- Apps import and register only the Plugin modules their backend uses.
- Plugin Backend contracts and tests gain Locality within their package targets.
- The namespaced Interface becomes the primary test surface.
- SwiftUI failures are no longer silently converted into status text.
- Platform claims are backed by compilation gates, not local device ownership.
