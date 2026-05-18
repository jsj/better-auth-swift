#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKER_DIR="$ROOT/examples/cf-workers-swiftui/worker"
PORT="${BETTER_AUTH_LOCAL_CONTRACT_PORT:-8797}"
BASE_URL="http://127.0.0.1:$PORT"
PERSIST_TO="$(mktemp -d "${TMPDIR:-/tmp}/better-auth-contract-d1.XXXXXX")"
WORKER_LOG="$(mktemp "${TMPDIR:-/tmp}/better-auth-contract-worker.XXXXXX")"
EMAIL="swift-contract-$(date +%s)-$$@example.com"
PASSWORD="${BETTER_AUTH_LOCAL_CONTRACT_PASSWORD:-Password123456!}"
WORKER_PID=""

usage() {
  cat <<'USAGE'
Usage: Scripts/run_local_contracts.sh

Starts the local Cloudflare Workers fixture backend with a fresh D1 store, then
runs LiveBetterAuthContractTests with fixture provisioning, JWKS, and anonymous
coverage enabled.

Environment:
  BETTER_AUTH_LOCAL_CONTRACT_PORT       Port for wrangler dev. Default: 8797
  BETTER_AUTH_LOCAL_CONTRACT_PASSWORD   Password for generated contract user.
USAGE
}

cleanup() {
  if [ -n "$WORKER_PID" ] && kill -0 "$WORKER_PID" >/dev/null 2>&1; then
    kill "$WORKER_PID" >/dev/null 2>&1 || true
    wait "$WORKER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$PERSIST_TO"
}

wait_for_health() {
  local deadline=$((SECONDS + 60))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -fsS "$BASE_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    if [ -n "$WORKER_PID" ] && ! kill -0 "$WORKER_PID" >/dev/null 2>&1; then
      echo "Local contract worker exited early. Log:" >&2
      cat "$WORKER_LOG" >&2
      return 1
    fi
    sleep 1
  done

  echo "Timed out waiting for local contract worker at $BASE_URL. Log:" >&2
  cat "$WORKER_LOG" >&2
  return 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for tool in curl npm npx swift; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for local contract verification." >&2
    exit 127
  fi
done

trap cleanup EXIT

echo "Preparing fresh local D1 store..."
(cd "$WORKER_DIR" && npx wrangler d1 migrations apply DB --local --persist-to "$PERSIST_TO")

echo "Starting local Better Auth fixture backend on $BASE_URL..."
(
  cd "$WORKER_DIR"
  npm run dev -- \
    --port "$PORT" \
    --persist-to "$PERSIST_TO" \
    --var "BETTER_AUTH_URL:$BASE_URL" \
    --var "TRUSTED_ORIGIN:$BASE_URL" \
    --var "APPLE_AUTH_MODE:emulated" \
    --var "APPLE_EMULATOR_BASE_URL:http://127.0.0.1:4010" \
    --var "GOOGLE_AUTH_MODE:fixture"
) >"$WORKER_LOG" 2>&1 &
WORKER_PID="$!"

wait_for_health

echo "Running live Better Auth contract tests against $BASE_URL..."
(
  cd "$ROOT"
  BETTER_AUTH_CONTRACT_BASE_URL="$BASE_URL" \
    BETTER_AUTH_CONTRACT_EMAIL="$EMAIL" \
    BETTER_AUTH_CONTRACT_PASSWORD="$PASSWORD" \
    BETTER_AUTH_CONTRACT_REQUEST_ORIGIN="$BASE_URL" \
    BETTER_AUTH_CONTRACT_PROVISION_WITH_FIXTURES=true \
    BETTER_AUTH_CONTRACT_SUPPORTS_ANONYMOUS=true \
    BETTER_AUTH_CONTRACT_EXPECT_JWKS=true \
    swift test --enable-swift-testing --filter LiveBetterAuthContractTests
)

echo "Local live contract verification passed."
