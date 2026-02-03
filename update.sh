#!/usr/bin/env bash
set -euo pipefail

# Ensure uv is installed
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Ensure uv and installed tools are on PATH for this shell
export PATH="$HOME/.local/bin:$PATH"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.cache/uv}"
mkdir -p "$UV_CACHE_DIR"

# Update global tool from the current branch (force rebuild)
uv tool uninstall clawpwn >/dev/null 2>&1 || true
uv tool install . --force --reinstall --refresh --no-cache

echo "Updated global ClawPwn from the current branch."

if command -v python3 >/dev/null 2>&1; then
  if python3 - <<'PY'
import inspect
import clawpwn
import clawpwn.cli as c
print(f"clawpwn package: {clawpwn.__file__}")
scan_src = inspect.getsource(c.scan)
print(f"has ip-scan fix: {'No URL scheme detected' in scan_src and 'scan_host' in scan_src}")
PY
  then
    exit 0
  fi
  echo "Note: python3 couldn't import clawpwn from the global tool; trying uv tool run..."
fi

if command -v uv >/dev/null 2>&1; then
  UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.cache/uv}" uv tool run --from clawpwn python - <<'PY'
import inspect
import clawpwn
import clawpwn.cli as c
print(f"clawpwn package: {clawpwn.__file__}")
scan_src = inspect.getsource(c.scan)
print(f"has ip-scan fix: {'No URL scheme detected' in scan_src and 'scan_host' in scan_src}")
PY
else
  echo "Note: Could not verify installed code (python3 not available)."
fi
