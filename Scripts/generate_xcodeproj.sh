#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/bootstrap_runner_env.sh
source "$ROOT/Scripts/bootstrap_runner_env.sh"
cd "$ROOT"

if command -v xcodegen >/dev/null 2>&1; then
  xcodegen generate --spec "$ROOT/project.yml"
  exit 0
fi

echo "xcodegen is not installed; using committed Xcode project" >&2
