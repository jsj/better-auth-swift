#!/usr/bin/env bash
set -euo pipefail

# Extract all endpoint paths from a cloned better-auth repo.
# Usage: ./extract_upstream_endpoints.sh /path/to/better-auth

REPO="${1:?Usage: extract_upstream_endpoints.sh /path/to/better-auth}"

# Scan main package and standalone plugin packages (passkey, sso, etc.)
# Use -A2 to catch paths on the same line or up to 2 lines after createAuthEndpoint(
{
  grep -rn 'createAuthEndpoint(' "$REPO/packages/better-auth/src/" --include="*.ts" -A2 2>/dev/null || true
  grep -rn 'createAuthEndpoint(' "$REPO/packages/passkey/src/" --include="*.ts" -A2 2>/dev/null || true
  grep -rn 'createAuthEndpoint(' "$REPO/packages/sso/src/" --include="*.ts" -A2 2>/dev/null || true
  grep -rn 'createAuthEndpoint(' "$REPO/packages/api-key/src/" --include="*.ts" -A2 2>/dev/null || true
} | grep -v '\.test\.' \
  | grep '"/' \
  | sed 's/.*"\(\/[^"]*\)".*/\1/' \
  | sort -u
