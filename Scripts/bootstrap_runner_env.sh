#!/usr/bin/env bash
set -euo pipefail

if [ -f "$HOME/actions-runner/.path" ]; then
  RUNNER_PATH="$(tr -d '\r' < "$HOME/actions-runner/.path")"
  case ":$PATH:" in
    *":$RUNNER_PATH:"*) ;;
    *) export PATH="$RUNNER_PATH:$PATH" ;;
  esac
fi

export PATH="$HOME/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
