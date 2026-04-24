#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/bootstrap_runner_env.sh
source "$ROOT/Scripts/bootstrap_runner_env.sh"
cd "$ROOT"

if command -v tuist >/dev/null 2>&1; then
  tuist generate --path "$ROOT"
  exit 0
fi

echo "tuist is required to generate the Xcode project. Install with: curl -Ls https://install.tuist.io | bash" >&2
exit 1
