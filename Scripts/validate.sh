#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT"

log() {
  printf '\n==> %s\n' "$1"
}

run_swift_tests() {
  log "Running package tests"
  swift test --enable-swift-testing

  if [ -d .build ] && [ -z "$(find .build -type f -print -quit 2>/dev/null)" ]; then
    echo "SwiftPM left an empty .build directory"
  fi
}

run_swiftformat_lint() {
  if ! command -v swiftformat >/dev/null 2>&1; then
    echo "SwiftFormat not found, skipping formatting check"
    return 0
  fi

  log "Running SwiftFormat lint"
  swiftformat . --lint --config .swiftformat
}

run_swiftlint() {
  if ! command -v swiftlint >/dev/null 2>&1; then
    echo "SwiftLint not found, skipping linting"
    return 0
  fi

  log "Running SwiftLint"
  swiftlint --config .swiftlint.yml --strict
}

main() {
  run_swift_tests
  run_swiftformat_lint
  run_swiftlint
}

main "$@"
