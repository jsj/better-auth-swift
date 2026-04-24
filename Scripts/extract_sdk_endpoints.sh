#!/usr/bin/env bash
set -euo pipefail

# Extract all endpoint paths the SDK covers from BetterAuthConfiguration.
# Strips the /api/auth prefix to match upstream's relative paths.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

grep 'Path.*=' "$ROOT/Sources/BetterAuthSwift/Configuration/BetterAuthConfiguration.swift" \
  | grep '"/api/auth' \
  | sed 's/.*"\(\/api\/auth[^"]*\)".*/\1/' \
  | sed 's|/api/auth||' \
  | sort -u
