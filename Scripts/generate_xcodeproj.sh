#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/bootstrap_runner_env.sh
source "$ROOT/Scripts/bootstrap_runner_env.sh"
cd "$ROOT"

if command -v xcodegen >/dev/null 2>&1; then
  echo "xcodegen is deprecated for this repo; install Tuist and run generation with it" >&2
fi

if command -v tuist >/dev/null 2>&1; then
  tuist generate --path "$ROOT"
  exit 0
fi

echo "tuist is not installed; using committed Xcode project. Install with: curl -Ls https://install.tuist.io | bash" >&2
