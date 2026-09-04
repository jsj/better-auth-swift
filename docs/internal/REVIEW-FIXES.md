# Review fixes

Implemented the six review findings and consolidated the example routes.

- [x] Standard Better Auth email paths and token/user envelopes; preserve custom full-session responses.
- [x] Actor-owned session commits reject stale refresh/fetch results across authentication changes and credential rotation. Concurrent profile changes survive refresh completion in either order.
- [x] Removed cached relay/service cycles. Sleeping and fired timers do not retain the manager during shutdown or unresponsive network I/O.
- [x] Mutations require explicit transient retry opt-in. Token-consuming GETs (email verification, magic links, OAuth callbacks) opt out too.
- [x] Local sign-out commits before remote revocation. Network failures are still reported without restoring local authentication.
- [x] The README SwiftUI example uses public `AuthStore.perform`; the release verifier compiles the exact snippet as a separate consumer.
- [x] Both example workers use one authored route source. Wrangler regenerates and hot-reloads it while preserving each worker's own auth configuration.
- [x] Full release verifier passed, including the Apple-platform matrix and final symbol/lint checks.

## Validation evidence

- `Scripts/verify_release.sh`: passed release compilation, all 45 product/platform builds across iOS, macOS, watchOS, visionOS, and tvOS, nine DocC builds, public API checks, formatting, and strict lint with zero violations.
- Full Swift suite in the release verifier: 173 core tests, 15 organization tests, 13 magic-link tests, 5 auth-module tests; live tests are disabled without their fixture environment.
- Magic-link suite rerun after the final retry opt-out: passed, including request and verification retry cases.
- `Scripts/run_upstream_contracts.sh`: passed against Better Auth 1.7.1 with an unmodified handler and the bearer plugin. Covers signup, signin, refresh, reauthentication, password reset, and revoked-session `200 null` cleanup.
- `Scripts/run_local_contracts.sh`: Cloudflare email lifecycle, JWKS, and anonymous contracts passed, including a repeated run. Optional username fixture is not configured.
- Both workers: 81 tests passed each; both TypeScript checks passed.
- `python3 Scripts/verify_quick_start.py`: passed.
- Running-worker reload probe: both workers reloaded a shared-source edit and its restoration.
- `swiftformat . --lint --config .swiftformat`: passed.
- Fresh-context reviews of concurrency/retry and compatibility/shared-worker changes completed; findings were fixed and re-reviewed.

## Compatibility notes

Email defaults now target upstream paths. Custom paths remain configurable. A tokenless signup cannot reveal whether email verification or disabled automatic signin caused it; `SuccessfulEmailSignUp.requiresVerification` is optional to represent that uncertainty. `allowsTransientRetry` defaults to automatic method-based eligibility; explicit booleans still override it.

The contract runner previously left orphaned Wrangler/workerd children. It now owns a separate process group, rejects occupied ports before health checks, and removes the worker group before deleting its temporary database.

Current verification log: `/tmp/better-auth-release-verification.log`.
