#!/bin/sh
set -eu

if [ "${BUILD_XCFRAMEWORKS:-0}" != "1" ]; then
  echo "BUILD_XCFRAMEWORKS is not enabled; skipping xcframework packaging"
  exit 0
fi

ROOT="${CI_WORKSPACE:-$(cd "$(dirname "$0")/.." && pwd)}"
ARTIFACTS_DIR="${CI_ARTIFACTS_DIR:-$ROOT/ci_artifacts}"
mkdir -p "$ARTIFACTS_DIR"

"$ROOT/Scripts/build_xcframeworks.sh" "$ARTIFACTS_DIR"
