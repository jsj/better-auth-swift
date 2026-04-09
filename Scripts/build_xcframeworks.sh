#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=Scripts/bootstrap_runner_env.sh
source "$ROOT/Scripts/bootstrap_runner_env.sh"
PROJECT="$ROOT/better-auth-swift.xcodeproj"
OUTPUT_DIR="${1:-$ROOT/build/xcframeworks}"
DERIVED_DATA_PATH="${DERIVED_DATA_PATH:-$ROOT/.build/xcode-derived-data}"
ARCHIVE_ROOT="$ROOT/.build/archives"
SCHEMES=("BetterAuth" "BetterAuthSwiftUI" "BetterAuthOrganization")

rm -rf "$OUTPUT_DIR" "$ARCHIVE_ROOT"
mkdir -p "$OUTPUT_DIR" "$ARCHIVE_ROOT"

"$ROOT/Scripts/generate_xcodeproj.sh"

archive_scheme() {
  local scheme="$1"
  local destination="$2"
  local suffix="$3"
  local archive_path="$ARCHIVE_ROOT/${scheme}-${suffix}.xcarchive"

  xcodebuild archive \
    -project "$PROJECT" \
    -scheme "$scheme" \
    -configuration Release \
    -destination "$destination" \
    -archivePath "$archive_path" \
    -derivedDataPath "$DERIVED_DATA_PATH" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES
}

for scheme in "${SCHEMES[@]}"; do
  archive_scheme "$scheme" "generic/platform=iOS" "ios"
  archive_scheme "$scheme" "generic/platform=iOS Simulator" "ios-simulator"
  archive_scheme "$scheme" "generic/platform=macOS" "macos"

  FRAMEWORK_NAME="${scheme}.framework"
  XCFRAMEWORK_PATH="$OUTPUT_DIR/${scheme}.xcframework"

  xcodebuild -create-xcframework \
    -framework "$ARCHIVE_ROOT/${scheme}-ios.xcarchive/Products/Library/Frameworks/$FRAMEWORK_NAME" \
    -framework "$ARCHIVE_ROOT/${scheme}-ios-simulator.xcarchive/Products/Library/Frameworks/$FRAMEWORK_NAME" \
    -framework "$ARCHIVE_ROOT/${scheme}-macos.xcarchive/Products/Library/Frameworks/$FRAMEWORK_NAME" \
    -output "$XCFRAMEWORK_PATH"

  ditto -c -k --sequesterRsrc --keepParent "$XCFRAMEWORK_PATH" "$OUTPUT_DIR/${scheme}.xcframework.zip"
done
