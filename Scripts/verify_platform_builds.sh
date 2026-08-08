#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT="$ROOT/better-auth-swift.xcodeproj"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-$ROOT/.build/platform-derived-data}"
SCHEMES=("BetterAuth" "BetterAuthMagicLink" "BetterAuthSwiftUI" "BetterAuthOrganization")
PLATFORMS=(
  "iOS|generic/platform=iOS"
  "macOS|generic/platform=macOS"
  "watchOS|generic/platform=watchOS"
  "visionOS|generic/platform=visionOS"
  "tvOS|generic/platform=tvOS"
)

"$ROOT/Scripts/generate_xcodeproj.sh"

for platform in "${PLATFORMS[@]}"; do
  platform_name="${platform%%|*}"
  destination="${platform#*|}"

  for scheme in "${SCHEMES[@]}"; do
    echo "Building $scheme for $platform_name..."
    xcodebuild build \
      -project "$PROJECT" \
      -scheme "$scheme" \
      -configuration Release \
      -destination "$destination" \
      -derivedDataPath "$DERIVED_DATA_PATH" \
      CODE_SIGNING_ALLOWED=NO
  done
done

echo "All public products compile for every supported Apple platform."
