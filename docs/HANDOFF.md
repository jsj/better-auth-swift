# Handoff

## Branch and state
- Branch: `jsj/refine`
- Repo has many in-progress changes already staged in the working tree; do not assume only the latest edits are relevant.
- Latest validation status at handoff:
  - `swift build --package-path "/Users/james/Developer/zrepos/zmirror/better-auth-swift"` passed
  - `swift test --package-path "/Users/james/Developer/zrepos/zmirror/better-auth-swift" --parallel` passed

## Original plan

### Phase 1: Refactor the core around seams
1. Split `BetterAuthSessionManager` into focused services:
   - `SessionService`
   - `SessionRefreshService`
   - `AuthFlowService`
   - `DeepLinkAuthHandler`
   - `UserAccountService`
2. Break `BetterAuthModels.swift` into domain files by feature.
3. Keep `BetterAuthClient` as the composition root only.

### Phase 2: Introduce stable protocols
1. Define protocols for:
   - transport
   - session storage
   - auth state store/observer
   - provider-specific auth flows
2. Make `BetterAuthSwiftUI` and `BetterAuthOrganization` consume those protocols rather than concrete manager internals.
3. Hide default implementations as internal where possible.

### Phase 3: Make auth state a first-class async primitive
1. Standardize on a single auth state model.
2. Expose:
   - `AsyncStream<AuthStateChange>`
   - current snapshot access
   - explicit restore/refresh transitions
3. Ensure all flows emit through the same path.

### Phase 4: Add a lightweight plugin/module system
1. Create a `BetterAuthPlugin` / `BetterAuthModule` contract.
2. Let modules register:
   - feature clients
   - endpoints/config
   - request hooks/interceptors
   - auth-state listeners
3. Move organization and future optional features onto that pattern.

### Phase 5: Expand test taxonomy
1. Unit tests:
   - model decoding
   - error mapping
   - state transitions
2. Integration tests:
   - request/response contracts
   - persistence + restore behavior
   - refresh/retry behavior
3. Smoke tests:
   - sign-in
   - restore
   - refresh
   - sign-out
   across SPM and generated Xcode project paths.

### Phase 6: Codify API and release discipline
1. Define API rules for:
   - naming
   - access control
   - typed errors
   - `Sendable`
   - actor isolation
2. Enforce validation in CI for:
   - SPM build/test
   - Xcode project generation
   - formatting/linting
   - smoke coverage

## Completed so far

### Phase 1
- Extracted core seams from `BetterAuthSessionManager` into focused services.
- Added callback/deep-link handling seam.
- Split former `BetterAuthModels.swift` into domain files:
  - `BetterAuthSessionModels.swift`
  - `BetterAuthSocialModels.swift`
  - `BetterAuthPasskeyModels.swift`
  - `BetterAuthOTPModels.swift`
- `BetterAuthClient` remains the composition root.

### Phase 2
- Added protocol surfaces in `Sources/BetterAuthSwift/BetterAuthClientProtocols.swift`.
- `OrganizationManager` now depends on protocol-based request access.
- Added broader auth performer abstraction and migrated `AuthStore` to use it instead of concrete `client.auth` calls.

### Phase 3
- Added explicit auth-state primitives and transitions.
- `AuthStateChange` now carries transition metadata.
- `AuthStore` derives launch state from structured transition phases.

### Phase 4
- Added module system primitives in `Sources/BetterAuthSwift/BetterAuthModules.swift`.
- `BetterAuthClient` now supports optional modules.
- Added `BetterAuthOrganizationModule` as the first concrete module.
- Added typed module runtime access via `BetterAuthModuleSupporting`.
- Fixed an important registry-construction bug so later modules can see already-registered runtimes during configuration.

### Phase 5
- Large Swift test suite was split into:
  - `BetterAuthSwiftTestsPart1.swift`
  - `BetterAuthSwiftTestsPart2.swift`
  - `BetterAuthSwiftTestsPart3.swift`
  - `BetterAuthSwiftTestsPart4.swift`
- Added/updated tests around:
  - auth state transitions
  - module registration
  - typed organization module access
- Current Swift tests are passing again.

## Important recent fixes
- Fixed a real test bug where `signedIn` was captured before declaration in `BetterAuthSwiftTestsPart1.swift`.
- Fixed a real module bug where module configuration previously received an always-empty registry snapshot.

## Best next steps
1. Finish deeper Phase 4 work:
   - move beyond identifiers/runtimes into richer typed feature registration
   - consider request hooks/interceptors and auth-state listener registration
   - migrate more optional features onto the module pattern
2. Advance Phase 6:
   - codify API/concurrency rules in code structure
   - inspect CI workflows and enforce the intended validation matrix
3. Continue Phase 5 deliberately:
   - make test taxonomy clearer as unit vs integration vs smoke
   - add explicit smoke coverage for SPM and generated Xcode project paths

## Files most relevant to continue from
- `Sources/BetterAuthSwift/BetterAuthClient.swift`
- `Sources/BetterAuthSwift/BetterAuthClientProtocols.swift`
- `Sources/BetterAuthSwift/BetterAuthModules.swift`
- `Sources/BetterAuthSwift/BetterAuthSessionState.swift`
- `Sources/BetterAuthSwift/BetterAuthSessionManager.swift`
- `Sources/BetterAuthSwiftUI/AuthStore.swift`
- `Sources/BetterAuthOrganization/BetterAuthOrganizationModule.swift`
- `Sources/BetterAuthOrganization/OrganizationManager.swift`
- `Tests/BetterAuthOrganizationTests/OrganizationTests.swift`
- `Tests/BetterAuthSwiftTests/BetterAuthSwiftTestsPart1.swift`
- `Tests/BetterAuthSwiftTests/BetterAuthSwiftTestsPart2.swift`
- `Tests/BetterAuthSwiftTests/BetterAuthSwiftTestsPart3.swift`
- `Tests/BetterAuthSwiftTests/BetterAuthSwiftTestsPart4.swift`

## Suggested first prompt for the next session
- "Read `HANDOFF.md`, inspect the current diffs, then continue with Phase 4 deeper module capabilities and Phase 6 validation discipline."
