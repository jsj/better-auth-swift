#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQUIRE_LIVE_CONTRACTS=0
VERSION=""

usage() {
  cat <<'USAGE'
Usage: Scripts/verify_release.sh [--version vMAJOR.MINOR.PATCH] [--require-live-contracts]

Runs the release verification gates:
  - swift build -c release
  - swift test --enable-swift-testing
  - public symbol graph guard for the BetterAuth API surface
  - swiftformat . --lint --config .swiftformat
  - swiftlint --config .swiftlint.yml --strict
  - live contract tests when Better Auth contract environment variables are configured

Use --require-live-contracts for release candidates where the live Better Auth
contract suite must run rather than be skipped.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        echo "--version requires a value such as v1.2.3" >&2
        exit 2
      fi
      VERSION="$2"
      shift 2
      ;;
    --require-live-contracts)
      REQUIRE_LIVE_CONTRACTS=1
      shift
      ;;
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

cd "$ROOT"

if [ -n "$VERSION" ] && [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$ ]]; then
  echo "Version must look like vMAJOR.MINOR.PATCH, got: $VERSION" >&2
  exit 2
fi

for tool in swift swiftformat swiftlint; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for release verification." >&2
    exit 127
  fi
done

echo "Building release package..."
swift build -c release

echo "Running package tests..."
swift test --enable-swift-testing

echo "Checking public symbol surface..."
swift package dump-symbol-graph --minimum-access-level public >/tmp/better-auth-swift-symbolgraph.log
SYMBOL_GRAPH="$(find .build -path '*/symbolgraph/BetterAuth.symbols.json' -type f -print | head -n 1)"
if [ -z "$SYMBOL_GRAPH" ]; then
  cat /tmp/better-auth-swift-symbolgraph.log >&2
  echo "Could not find BetterAuth public symbol graph." >&2
  exit 1
fi

if grep -q "BetterAuthSessionManager" "$SYMBOL_GRAPH"; then
  echo "BetterAuthSessionManager leaked into the public BetterAuth symbol graph." >&2
  exit 1
fi

if ! grep -q "BetterAuthAuthClient" "$SYMBOL_GRAPH"; then
  echo "BetterAuthAuthClient is missing from the public BetterAuth symbol graph." >&2
  exit 1
fi

echo "Checking formatting..."
swiftformat . --lint --config .swiftformat

echo "Running SwiftLint..."
swiftlint --config .swiftlint.yml --strict

if [ -n "${BETTER_AUTH_CONTRACT_BASE_URL:-}" ] &&
  [ -n "${BETTER_AUTH_CONTRACT_EMAIL:-}" ] &&
  [ -n "${BETTER_AUTH_CONTRACT_PASSWORD:-}" ]; then
  echo "Running live Better Auth contract tests..."
  swift test --enable-swift-testing --filter LiveBetterAuthContractTests
elif [ "$REQUIRE_LIVE_CONTRACTS" -eq 1 ]; then
  cat >&2 <<'ERROR'
Live contract tests are required, but the required environment variables are missing:
  BETTER_AUTH_CONTRACT_BASE_URL
  BETTER_AUTH_CONTRACT_EMAIL
  BETTER_AUTH_CONTRACT_PASSWORD
ERROR
  exit 1
else
  echo "Skipping live contract tests; BETTER_AUTH_CONTRACT_* environment is not configured."
fi

if [ -n "$VERSION" ]; then
  echo "Release verification passed for $VERSION."
else
  echo "Release verification passed."
fi
