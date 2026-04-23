# AGENTS.md

## Current validation status

Primary blocker resolved:

```bash
swift test --enable-swift-testing
```

This command now exits `0` locally.

Root cause found: `BetterAuthRequestPerforming` default `sendJSON(... body: some Encodable ...)` recursively dispatched through an existential (`any BetterAuthRequestPerforming`) for organization POST requests. The visible Swift Testing output could show many passed tests while the recursive organization tests never completed, causing the raw command to exit nonzero.

## Validation commands

swift test --enable-swift-testing
swiftformat . --lint --config .swiftformat
swiftlint --config .swiftlint.yml --strict
```

Prefer direct commands over wrapper scripts when debugging validation failures.
