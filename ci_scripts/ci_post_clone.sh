#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/Scripts/generate_xcodeproj.sh"
