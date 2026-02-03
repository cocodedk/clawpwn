#!/usr/bin/env bash
set -euo pipefail

# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Ensure uv is on PATH for this shell
if ! command -v uv >/dev/null 2>&1; then
  export PATH="$HOME/.local/bin:$PATH"
fi

# Sync dependencies (including dev tools)
uv sync --extra dev

# Use repo-local caches to avoid permission issues
export PRE_COMMIT_HOME="${PRE_COMMIT_HOME:-$PWD/.cache/pre-commit}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.cache/uv}"
mkdir -p "$PRE_COMMIT_HOME" "$UV_CACHE_DIR"

# Install pre-commit hooks
uv run pre-commit install

echo "Setup complete. Run 'uv run pytest' to verify."
