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
  local val
  line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null || true)"
  val="${line#*=}"
  # Strip trailing carriage return and newline so we never write multi-line values
  while [[ "$val" = *$'\n' ]]; do val="${val%$'\n'}"; done
  while [[ "$val" = *$'\r' ]]; do val="${val%$'\r'}"; done
  printf "%s" "$val"
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

# Write the entire .env once from env_values (no partial updates).
write_env_file() {
  local key
  local val
  if command -v python3 >/dev/null 2>&1; then
    (
      datafile="$(mktemp)"
      trap 'rm -f "$datafile"' EXIT
      printf "%s\n" "$ENV_FILE" > "$datafile"
      for key in "${required_keys[@]}"; do
        val="${env_values[$key]:-}"
        val="${val//$'\n'/}"
        val="${val//$'\r'/}"
        printf "%s=%s\n" "$key" "$val" >> "$datafile"
      done
      python3 - "$datafile" <<'PY'
import sys
from pathlib import Path

with open(sys.argv[1]) as f:
    lines = f.read().splitlines()
path = Path(lines[0])
out = [line for line in lines[1:] if "=" in line]
path.write_text(chr(10).join(out) + chr(10))
PY
    )
  else
    : > "$ENV_FILE"
    for key in "${required_keys[@]}"; do
      val="${env_values[$key]:-}"
      val="${val//$'\n'/}"
      val="${val//$'\r'/}"
      printf "%s=%s\n" "$key" "$val" >> "$ENV_FILE"
    done
  fi
}

# Show current value (including for API key) and hint. Then read; if user presses Enter
# and current is non-empty, return current; otherwise return user input.
# Messages go to stderr so they are visible when stdout is captured (val="$(prompt_value ...)").
prompt_value() {
  local key="$1"
  local prompt="$2"
  local secret="${3:-false}"
  local current="$4"
  local value
  if [ -n "$current" ]; then
    echo "  Current value: $current" >&2
  else
    echo "  Current value: (empty)" >&2
  fi
  echo "  (Press Enter to keep current value, or enter a new value. If current is empty, you must enter a value to set one.)" >&2
  if [ "$secret" = "true" ]; then
    read -r -s -p "$prompt: " value
    echo >&2
  else
    read -r -p "$prompt: " value
  fi
  if [ -z "$value" ] && [ -n "$current" ]; then
    printf "%s" "$current"
  else
    printf "%s" "$value"
  fi
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

declare -A env_values
for key in "${required_keys[@]}"; do
  current="$(get_current_value "$key")"
  case "$key" in
      "CLAWPWN_LLM_PROVIDER")
        val="$(prompt_value "$key" "LLM provider (e.g., openai, anthropic, local)" "false" "$current")"
        provider_value="$val"
        ;;
      "CLAWPWN_LLM_API_KEY")
        val="$(prompt_value "$key" "LLM API key" "true" "$current")"
        ;;
      "CLAWPWN_LLM_BASE_URL")
        if [ "${provider_value:-${CLAWPWN_LLM_PROVIDER:-}}" = "openrouter" ]; then
          if [ -n "$current" ]; then echo "  Current value: $current" >&2; else echo "  Current value: (empty)" >&2; fi
          val="https://openrouter.ai/api/v1"
          echo "  Using OpenRouter base URL: $val" >&2
        else
          val="$(prompt_value "$key" "LLM base URL (optional)" "false" "$current")"
        fi
        ;;
      "CLAWPWN_LLM_MODEL")
        val="$(prompt_value "$key" "Default model (e.g., gpt-4.1)" "false" "$current")"
        ;;
      "CLAWPWN_DATA_DIR")
        val="$(prompt_value "$key" "Data directory (optional, leave blank for default)" "false" "$current")"
        ;;
      "CLAWPWN_VERBOSE")
        val="$(prompt_value "$key" "Verbose logging (true/false)" "false" "$current")"
        ;;
      *)
        val="$(prompt_value "$key" "Value for $key" "false" "$current")"
        ;;
    esac
  val="${val//$'\n'/}"
  val="${val//$'\r'/}"
  env_values["$key"]="$val"
done

write_env_file

echo "Installed. Ensure ~/.local/bin is on your PATH, then run: clawpwn --help"
