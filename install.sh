#!/usr/bin/env bash
set -euo pipefail

# Ensure uv is installed
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

# Ensure uv and installed tools are on PATH for this shell
export PATH="$HOME/.local/bin:$PATH"

# Install ClawPwn as a global tool
uv tool install . --force

# Ensure masscan is installed (optional; use --scanner masscan)
if ! command -v masscan >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "Installing masscan (requires sudo)..."
    sudo apt-get update
    sudo apt-get install -y masscan
  else
    echo "Warning: masscan not found and apt-get unavailable. Install masscan manually for --scanner masscan."
  fi
fi

# Ensure rustscan is installed (default scanner)
if ! command -v rustscan >/dev/null 2>&1; then
  if command -v cargo >/dev/null 2>&1; then
    echo "Installing rustscan via cargo..."
    cargo install rustscan
  elif command -v apt-get >/dev/null 2>&1; then
    echo "Installing rustscan (requires sudo)..."
    sudo apt-get update
    sudo apt-get install -y rustscan 2>/dev/null || echo "Warning: rustscan package may not be in your distro. Install with: cargo install rustscan"
  else
    echo "Warning: rustscan not found. Install with: cargo install rustscan (or use --scanner masscan/nmap)."
  fi
fi

# --- Network Scanner Permissions ---
if [ "$(uname)" = "Linux" ] && command -v setcap >/dev/null 2>&1; then
  echo ""
  echo "=== Network Scanner Permissions ==="
  echo ""
  echo "ClawPwn's network scanners (masscan, rustscan) need raw socket access"
  echo "for SYN scans and service detection. This requires elevated privileges."
  echo ""
  echo "Options:"
  echo "  1. Set capabilities on scanner binaries (recommended for work machines)"
  echo "     Grants only raw network access to those binaries; no sudo needed for scans."
  echo ""
  echo "  2. Skip and use sudo when scanning: sudo clawpwn scan ..."
  echo ""
  read -r -p "Set capabilities on scanner binaries? [y/N]: " setup_caps || true
  if [[ "${setup_caps:-}" =~ ^[Yy]$ ]]; then
    for bin in masscan rustscan; do
      bin_path="$(command -v "$bin" 2>/dev/null || true)"
      if [ -n "$bin_path" ]; then
        echo "Setting cap_net_raw on $bin_path..."
        if sudo setcap cap_net_raw+ep "$bin_path" 2>/dev/null; then
          echo "  Done: $bin_path"
        else
          echo "  Failed: $bin_path (you may need to use sudo for scans)"
        fi
      fi
    done
  else
    echo "Skipped. Run scans with: sudo clawpwn scan ... (or run this script again to set capabilities)"
  fi
  echo ""
fi

# Resolve .env path relative to install.sh so we never overwrite the wrong file
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
if [ ! -f "$ENV_FILE" ]; then
  touch "$ENV_FILE"
fi

FORCE=false
if [ "${1:-}" = "--force" ]; then
  FORCE=true
fi

get_env_value() {
  local key="$1"
  local line
  line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null || true)"
  printf "%s" "${line#*=}"
}

# Consider key "set" if it exists in .env or in the current environment (so we don't prompt again)
get_current_value() {
  local key="$1"
  local current
  current="$(get_env_value "$key")"
  if [ -z "$current" ]; then
    # Bash indirect expansion: ${!key} is the value of the variable named by key
    current="${!key:-}"
  fi
  printf "%s" "$current"
}

set_env_value() {
  local key="$1"
  local value="$2"
  if command -v python3 >/dev/null 2>&1; then
    printf "%s\n%s\n%s\n" "$key" "$value" "$ENV_FILE" | python3 - <<'PY'
from pathlib import Path
import re
import sys

data = sys.stdin.read().splitlines()
key = data[0] if data else ""
value = data[1] if len(data) > 1 else ""
path = Path(data[2]) if len(data) > 2 else Path(".env")

lines = path.read_text().splitlines() if path.exists() else []
found = False
out = []
for line in lines:
    if re.match(rf"^{re.escape(key)}=", line):
        out.append(f"{key}={value}")
        found = True
    else:
        out.append(line)

if not found:
    out.append(f"{key}={value}")

path.write_text("\\n".join(out) + "\\n")
PY
  else
    # Fallback (best-effort) without python3
    if grep -qE "^${key}=" "$ENV_FILE"; then
      awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="} $1==k{$2=v} {print}' "$ENV_FILE" > "$ENV_FILE.tmp"
      mv "$ENV_FILE.tmp" "$ENV_FILE"
    else
      printf "%s=%s\n" "$key" "$value" >> "$ENV_FILE"
    fi
  fi
}

prompt_value() {
  local key="$1"
  local prompt="$2"
  local secret="${3:-false}"
  local value
  if [ "$secret" = "true" ]; then
    read -r -s -p "$prompt: " value
    echo
  else
    read -r -p "$prompt: " value
  fi
  printf "%s" "$value"
}

provider_value=""
required_keys=(
  "CLAWPWN_LLM_PROVIDER"
  "CLAWPWN_LLM_API_KEY"
  "CLAWPWN_LLM_BASE_URL"
  "CLAWPWN_LLM_MODEL"
  "CLAWPWN_DATA_DIR"
  "CLAWPWN_VERBOSE"
)

for key in "${required_keys[@]}"; do
  current="$(get_current_value "$key")"
  if [ -n "$current" ] && [ "$FORCE" != "true" ]; then
    echo "  $key already set, skipping (use --force to override)"
  elif [ -z "$current" ] || [ "$FORCE" = "true" ]; then
    case "$key" in
      "CLAWPWN_LLM_PROVIDER")
        val="$(prompt_value "$key" "LLM provider (e.g., openai, anthropic, local)")"
        provider_value="$val"
        ;;
      "CLAWPWN_LLM_API_KEY")
        val="$(prompt_value "$key" "LLM API key" "true")"
        ;;
      "CLAWPWN_LLM_BASE_URL")
        if [ "${provider_value:-${CLAWPWN_LLM_PROVIDER:-}}" = "openrouter" ]; then
          val="https://openrouter.ai/api/v1"
          echo "Using OpenRouter base URL: $val"
        else
          val="$(prompt_value "$key" "LLM base URL (optional)")"
        fi
        ;;
      "CLAWPWN_LLM_MODEL")
        val="$(prompt_value "$key" "Default model (e.g., gpt-4.1)")"
        ;;
      "CLAWPWN_DATA_DIR")
        val="$(prompt_value "$key" "Data directory (optional, leave blank for default)")"
        ;;
      "CLAWPWN_VERBOSE")
        val="$(prompt_value "$key" "Verbose logging (true/false)")"
        ;;
      *)
        val="$(prompt_value "$key" "Value for $key")"
        ;;
    esac
    set_env_value "$key" "$val"
  fi
done

echo "Installed. Ensure ~/.local/bin is on your PATH, then run: clawpwn --help"
