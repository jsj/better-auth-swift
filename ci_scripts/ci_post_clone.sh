#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

if ! command -v mise >/dev/null 2>&1; then
  curl https://mise.run | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

mise trust -y .mise.toml
mise install
mise exec -- tuist install --path .
mise exec -- tuist generate --no-open
