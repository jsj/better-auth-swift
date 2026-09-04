#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${BETTER_AUTH_UPSTREAM_PORT:-8798}"
BASE_URL="http://127.0.0.1:$PORT"
python3 - "$PORT" <<'PYPORT'
import socket, sys
with socket.socket() as listener:
    listener.bind(("127.0.0.1", int(sys.argv[1])))
PYPORT
LOG="$(mktemp "${TMPDIR:-/tmp}/better-auth-upstream.XXXXXX")"
BETTER_AUTH_UPSTREAM_PORT="$PORT" bun "$ROOT/examples/cf-workers-swiftui/worker/scripts/upstream-contract-server.ts" >"$LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for attempt in {1..60}; do
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$LOG" >&2
    exit 1
  fi
  if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
    cd "$ROOT"
    if BETTER_AUTH_UPSTREAM_BASE_URL="$BASE_URL" swift test --enable-swift-testing --filter UpstreamBetterAuthContractTests; then
      exit 0
    fi
    cat "$LOG" >&2
    exit 1
  fi
  sleep 1
done
cat "$LOG" >&2
exit 1
