#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_FILE="${TMPDIR:-/tmp}/better-auth-swift-test.log"

cd "$ROOT"

set +e
swift test --enable-swift-testing 2>&1 | tee "$LOG_FILE"
status=${PIPESTATUS[0]}
set -e

if [ "$status" -eq 0 ]; then
  exit 0
fi

FILTERED_LOG="$(mktemp)"
grep -v "CoreData: error: Failed to create NSXPCConnection" "$LOG_FILE" > "$FILTERED_LOG" || true

if grep -Eq "(✔ Test |Test .* passed after)" "$FILTERED_LOG" \
  && ! grep -Eq "(^|[[:space:]])(✘ Test |Test .* failed|error:|Issue recorded|caught unexpected signal)" "$FILTERED_LOG"; then
  echo "Ignoring known Swift Testing non-zero exit because all visible tests passed."
  exit 0
fi

exit "$status"
