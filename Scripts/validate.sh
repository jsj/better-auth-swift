#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT"

swift test --enable-swift-testing

if command -v swiftformat >/dev/null 2>&1; then
  swiftformat . --lint --config .swiftformat
else
  echo "SwiftFormat not found, skipping formatting check"
fi

if command -v swiftlint >/dev/null 2>&1; then
  swiftlint --config .swiftlint.yml --strict
else
  echo "SwiftLint not found, skipping linting"
fi
