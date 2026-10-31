# v0.1.1

## Changes

- Update both example backends, the passkey plugin, and the Better Auth CLI from 1.7.7 to 1.7.14.
- Complete native generic OAuth in the example backends, including state-cookie validation and replay rejection.
- Preserve OAuth compatibility and provide the account schema migration added after v0.1.0.
- Update compatibility documentation to identify the tested server version.

## Upgrade notes

The Swift package API and minimum platform versions are unchanged from v0.1.0.

For existing example databases, apply the included `0002_remove_account_issuer.sql` migration through your normal migration process.
Fresh databases must apply both migrations.

Before upgrading your backend, review the [Better Auth 1.7.12 changes](https://github.com/better-auth/better-auth/releases/tag/v1.7.12).
ID-token signin requires configured provider client IDs for audience validation.
The Apple examples configure a client ID and a native app bundle audience.

Native generic OAuth completion requires the example callback adapter or an equivalent backend implementation.
Use one cookie-enabled transport for initiation and completion.
See [backend compatibility](./backend-compatibility.md#native-generic-oauth).

## Local verification

Validated on 2026-10-31:

- `Scripts/verify_release.sh --version v0.1.1` passed, including all nine products on five Apple platforms, DocC, public API checks, formatting, and lint.
- Both workers passed typechecking and 84 tests each.
- `Scripts/test_account_migration.py` passed both migration tests.
- `Scripts/run_upstream_contracts.sh` passed against Better Auth 1.7.14.
- `Scripts/run_local_contracts.sh` passed email/session, generic OAuth replay, JWKS, and anonymous-auth coverage. Username coverage was not configured.
- `bun run --cwd examples/cf-workers-swiftui e2e:oauth` passed the Apple emulator authorization-code flow.
- Clean npm and frozen Bun installs passed.

The release verifier skipped externally configured live contracts. The local fixture and upstream contract suites ran separately.
GitHub Actions must pass for the release commit before tagging.

The existing Vitest and Wrangler/Miniflare dependency trees still report development-tool audit advisories.
Those tools were not upgraded in this Better Auth patch.
