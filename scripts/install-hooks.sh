#!/usr/bin/env bash
# Install the pre-commit, commit-msg and pre-push hooks.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
uv run pre-commit install --install-hooks \
  --hook-type pre-commit --hook-type commit-msg --hook-type pre-push
echo "Hooks installed: pre-commit, commit-msg, pre-push."
