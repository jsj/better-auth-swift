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
PLATFORMS=(
  "ios|generic/platform=iOS"
  "ios-simulator|generic/platform=iOS Simulator"
  "macos|generic/platform=macOS"
)

rm -rf "$OUTPUT_DIR" "$ARCHIVE_ROOT"
mkdir -p "$OUTPUT_DIR" "$ARCHIVE_ROOT"

"$ROOT/Scripts/generate_xcodeproj.sh"

archive_scheme() {
  local scheme="$1"
  local destination="$2"
  local suffix="$3"
  local archive_path="$ARCHIVE_ROOT/${scheme}-${suffix}.xcarchive"
  local log_path="$ARCHIVE_ROOT/${scheme}-${suffix}.log"

  if xcodebuild archive \
    -project "$PROJECT" \
    -scheme "$scheme" \
    -configuration Release \
    -destination "$destination" \
    -archivePath "$archive_path" \
    -derivedDataPath "$DERIVED_DATA_PATH" \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    > "$log_path" 2>&1; then
    return 0
  fi

  if grep -Eq "Unable to find a destination|is not installed" "$log_path"; then
    echo "Skipping $scheme archive for $destination because the platform is unavailable on this runner." >&2
    cat "$log_path" >&2
    return 2
  fi

  cat "$log_path" >&2
  return 1
}

for scheme in "${SCHEMES[@]}"; do
  FRAMEWORK_NAME="${scheme}.framework"
  XCFRAMEWORK_PATH="$OUTPUT_DIR/${scheme}.xcframework"
  CREATE_ARGS=()

  for platform in "${PLATFORMS[@]}"; do
    suffix="${platform%%|*}"
    destination="${platform#*|}"
    if archive_scheme "$scheme" "$destination" "$suffix"; then
      framework_path="$ARCHIVE_ROOT/${scheme}-${suffix}.xcarchive/Products/Library/Frameworks/$FRAMEWORK_NAME"
      if [ -d "$framework_path" ]; then
        CREATE_ARGS+=("-framework" "$framework_path")
      fi
    fi
  done

  if [ "${#CREATE_ARGS[@]}" -eq 0 ]; then
    echo "No archives were produced for $scheme" >&2
    exit 1
  fi

  xcodebuild -create-xcframework \
    "${CREATE_ARGS[@]}" \
    -output "$XCFRAMEWORK_PATH"

  ditto -c -k --sequesterRsrc --keepParent "$XCFRAMEWORK_PATH" "$OUTPUT_DIR/${scheme}.xcframework.zip"
done
