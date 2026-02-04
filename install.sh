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

# Ensure .env exists and has required keys
ENV_FILE=".env"
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

set_env_value() {
  local key="$1"
  local value="$2"
  if command -v python3 >/dev/null 2>&1; then
    printf "%s\n%s\n" "$key" "$value" | python3 - <<'PY'
from pathlib import Path
import re
import sys

path = Path(".env")
data = sys.stdin.read().splitlines()
key = data[0] if data else ""
value = data[1] if len(data) > 1 else ""

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
  current="$(get_env_value "$key")"
  if [ -z "$current" ] || [ "$FORCE" = "true" ]; then
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
