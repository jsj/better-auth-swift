# AGENTS.md

## Current investigation focus

Primary bug under investigation:

```bash
swift test --enable-swift-testing
```

On this repo, that command can exit with code `1` even when all visible tests and suites print as passed.

This is believed to be a real hidden failure or hidden issue-recording problem, not just wrapper-script noise.

## Important conclusions already established

- We removed wrapper indirection that was obscuring the problem:
  - deleted `Scripts/validate.sh`
  - deleted `Scripts/swift_test_wrapper.sh`
  - CI workflows were updated to call direct commands instead of those wrappers
- `swiftformat . --lint --config .swiftformat` passes
- `swiftlint --config .swiftlint.yml --strict` passes
- `swift test --enable-swift-testing` is the core reproduction path to trust
- Prior session evidence in `~/.factory/sessions/` indicates this is/was a real buried failure, not purely a fake SwiftPM exit
- Earlier investigation significantly narrowed the space to `SessionLifecycleCoreTests`
- A prior “fussy fix” (`await manager.stopAutoRefresh()`) was not sufficient by itself
- We should be skeptical of explanations that rely only on scripts/workflows; prefer raw reproduction first

## Prior session to consult

Review this session log first:

- `~/.factory/sessions/-Users-james-Developer-zrepos-zmirror-better-auth-swift/1f9918c1-bc74-4fe9-892f-53eb99d203f1.jsonl`

That session contains a lot of narrowing work and confirmed this was not merely a VM-only issue.

## Working assumptions

- The remaining exit-1 likely comes from:
  - a hidden issue recorded late in execution, or
  - async/background teardown behavior, or
  - a Swift Testing / SwiftPM interaction that still corresponds to a real underlying bad event in this package
- Do not assume the nonzero exit is harmless unless proven
- Do not reintroduce wrapper scripts to “paper over” the issue

## Recommended approach for the next agent/session

1. Start with the raw command only:

   ```bash
   swift test --enable-swift-testing
   ```

2. Capture full output to a file and inspect systematically, not just the tail

3. Compare:
   - direct host run
   - explicit `--parallel`
   - Tart VM reproduction
   - self-hosted runner behavior

4. Use prior session findings to continue narrowing toward:
   - the exact test
   - exact pair/order interaction
   - exact hidden issue emission point

5. Prefer direct commands over repo scripts/workflows during debugging

## Current repo cleanup state

Wrapper simplification already done:
- `.github/workflows/pr-ci.yml` now runs direct commands
- `.github/workflows/self-hosted-smoke.yml` now runs direct commands
- no need to restore deleted validation wrappers unless explicitly asked

## Goal

Find the true cause of the raw:

```bash
swift test --enable-swift-testing
```

exit code `1`, and make that command exit `0` for real.
