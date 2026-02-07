#!/usr/bin/env bash
set -euo pipefail

echo "=== ClawPwn Installer ==="
echo ""

# Get sudo upfront so we don't prompt multiple times
echo "This installer needs sudo for: installing scanners and setting permissions."
sudo -v || { echo "Error: sudo access required"; exit 1; }

# Keep sudo alive in background
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &

# Ensure uv is installed
if ! command -v uv >/dev/null 2>&1; then
  echo "[1/6] Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
else
  echo "[1/6] uv already installed"
fi

# Ensure Rust/cargo is installed
if ! command -v cargo >/dev/null 2>&1; then
  echo "[2/6] Installing Rust (cargo)..."
  curl -LsSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain stable
else
  echo "[2/6] Rust already installed"
fi

# Ensure PATH includes cargo and local bin
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
# Source cargo env if exists (for fresh installs)
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# Install ClawPwn
echo "[3/6] Installing ClawPwn..."
uv tool install . --force --reinstall --refresh

# Install scanners
echo "[4/6] Installing scanners (nmap, masscan, rustscan)..."

# nmap, masscan, and build tools via package manager
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y nmap masscan libcap2-bin build-essential >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y nmap masscan libcap gcc make >/dev/null 2>&1 || sudo dnf install -y nmap libcap gcc >/dev/null
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nmap masscan libcap gcc make >/dev/null 2>&1 || sudo yum install -y nmap libcap gcc >/dev/null
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -S --noconfirm nmap masscan libcap base-devel >/dev/null
elif command -v brew >/dev/null 2>&1; then
  brew install nmap masscan >/dev/null 2>&1 || brew install nmap >/dev/null
fi

# rustscan via cargo (NOT snap - snap can't get setcap)
echo "  Installing rustscan via cargo..."
cargo install rustscan --quiet 2>/dev/null || cargo install rustscan 2>/dev/null || true

# Verify scanners
for bin in nmap masscan rustscan; do
  if [ "$bin" = "rustscan" ] && [ -x "$HOME/.cargo/bin/rustscan" ]; then
    echo "  $bin: $HOME/.cargo/bin/rustscan"
  elif command -v "$bin" >/dev/null 2>&1; then
    echo "  $bin: $(command -v "$bin")"
  else
    echo "  $bin: NOT FOUND (optional)"
  fi
done

echo "[5/6] Installing web scanners (nuclei, feroxbuster, ffuf, nikto, sqlmap, testssl, wpscan, zap)..."

# Install web scanner packages via package manager when available
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y nikto ffuf feroxbuster sqlmap testssl.sh >/dev/null 2>&1 || true
  sudo apt-get install -y zaproxy >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y nikto ffuf feroxbuster sqlmap testssl zaproxy >/dev/null 2>&1 || true
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nikto ffuf feroxbuster sqlmap testssl zaproxy >/dev/null 2>&1 || true
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -S --noconfirm nikto ffuf feroxbuster sqlmap zaproxy >/dev/null 2>&1 || true
elif command -v brew >/dev/null 2>&1; then
  brew install nikto ffuf feroxbuster sqlmap testssl >/dev/null 2>&1 || true
  brew install --cask owasp-zap >/dev/null 2>&1 || true
fi

# wpscan via gem (Ruby-based)
if ! command -v wpscan >/dev/null 2>&1; then
  if command -v gem >/dev/null 2>&1; then
    echo "  Installing wpscan via gem..."
    sudo gem install wpscan --no-document >/dev/null 2>&1 || true
  fi
fi

# testssl.sh fallback via git if package not available
if ! command -v testssl.sh >/dev/null 2>&1 && ! command -v testssl >/dev/null 2>&1; then
  echo "  Installing testssl.sh via git..."
  if [ ! -d "$HOME/.local/share/testssl.sh" ]; then
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$HOME/.local/share/testssl.sh" >/dev/null 2>&1 || true
  fi
  if [ -f "$HOME/.local/share/testssl.sh/testssl.sh" ]; then
    ln -sf "$HOME/.local/share/testssl.sh/testssl.sh" "$HOME/.local/bin/testssl.sh" 2>/dev/null || true
  fi
fi

# Ensure Go is present for fallback installs
if ! command -v go >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y golang-go >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y golang >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y golang >/dev/null 2>&1 || true
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm go >/dev/null 2>&1 || true
  elif command -v brew >/dev/null 2>&1; then
    brew install go >/dev/null 2>&1 || true
  fi
fi

# Use local bin for Go-based tools
mkdir -p "$HOME/.local/bin"
export GOBIN="$HOME/.local/bin"

# Install nuclei and ffuf via Go fallback when missing
if ! command -v nuclei >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
  echo "  Installing nuclei via go install..."
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1 || true
fi
if ! command -v ffuf >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
  echo "  Installing ffuf via go install..."
  go install github.com/ffuf/ffuf/v2@latest >/dev/null 2>&1 || true
fi
if ! command -v feroxbuster >/dev/null 2>&1; then
  echo "  Installing feroxbuster via cargo..."
  cargo install feroxbuster --quiet >/dev/null 2>&1 || cargo install feroxbuster >/dev/null 2>&1 || true
fi

# sqlmap fallback via uv tool (Python-based, doesn't need sudo)
if ! command -v sqlmap >/dev/null 2>&1; then
  echo "  Installing sqlmap via uv tool..."
  uv tool install sqlmap >/dev/null 2>&1 || true
fi

# Verify web scanners
for bin in nuclei feroxbuster ffuf nikto sqlmap wpscan testssl.sh docker; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "  $bin: $(command -v "$bin")"
  else
    echo "  $bin: NOT FOUND (optional)"
  fi
done

# Set up passwordless sudo for scanners (Linux only)
echo "[6/6] Setting up scanner permissions..."
if [ "$(uname)" = "Linux" ]; then
  # Get scanner paths
  nmap_path="$(command -v nmap 2>/dev/null || true)"
  masscan_path="$(command -v masscan 2>/dev/null || true)"
  rustscan_path=""
  if [ -x "$HOME/.cargo/bin/rustscan" ]; then
    rustscan_path="$HOME/.cargo/bin/rustscan"
  else
    rustscan_path="$(command -v rustscan 2>/dev/null || true)"
  fi
  
  # Build sudoers rules
  sudoers_file="/etc/sudoers.d/clawpwn-scanners"
  sudoers_content="# ClawPwn scanner permissions - passwordless sudo for network scanners
# Created by install.sh
"
  if [ -n "$nmap_path" ]; then
    sudoers_content="${sudoers_content}$(whoami) ALL=(root) NOPASSWD: $nmap_path
"
  fi
  if [ -n "$masscan_path" ]; then
    sudoers_content="${sudoers_content}$(whoami) ALL=(root) NOPASSWD: $masscan_path
"
  fi
  if [ -n "$rustscan_path" ]; then
    sudoers_content="${sudoers_content}$(whoami) ALL=(root) NOPASSWD: $rustscan_path
"
  fi
  
  # Write sudoers file
  echo "$sudoers_content" | sudo tee "$sudoers_file" >/dev/null
  sudo chmod 440 "$sudoers_file"
  
  # Validate sudoers
  if sudo visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
    echo "  Sudoers configured: $sudoers_file"
    [ -n "$nmap_path" ] && echo "    nmap: OK (sudo without password)"
    [ -n "$masscan_path" ] && echo "    masscan: OK (sudo without password)"
    [ -n "$rustscan_path" ] && echo "    rustscan: OK (sudo without password)"
  else
    echo "  Warning: sudoers validation failed, removing file"
    sudo rm -f "$sudoers_file"
  fi
else
  echo "  Skipped (not Linux)"
fi

# Add PATH to shell profile if not already there
add_to_path() {
  local profile=""
  local line=""
  local is_fish=false
  
  # Detect shell profile
  if [ "$SHELL" = "/usr/bin/fish" ] || [ "$SHELL" = "/bin/fish" ]; then
    profile="$HOME/.config/fish/config.fish"
    line='fish_add_path -g $HOME/.cargo/bin $HOME/.local/bin'
    is_fish=true
    mkdir -p "$HOME/.config/fish"
  elif [ -n "${ZSH_VERSION:-}" ] || [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
    profile="$HOME/.zshrc"
    line='export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"'
  elif [ -n "${BASH_VERSION:-}" ] || [ "$SHELL" = "/bin/bash" ] || [ "$SHELL" = "/usr/bin/bash" ]; then
    profile="$HOME/.bashrc"
    line='export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"'
  elif [ -f "$HOME/.profile" ]; then
    profile="$HOME/.profile"
    line='export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"'
  fi
  
  if [ -n "$profile" ]; then
    # Check if already in profile
    if ! grep -qF '.cargo/bin' "$profile" 2>/dev/null; then
      echo "" >> "$profile"
      echo "# ClawPwn PATH" >> "$profile"
      echo "$line" >> "$profile"
      echo "  Added PATH to $profile"
    else
      echo "  PATH already in $profile"
    fi
    # Export for current shell (works for bash/zsh running this script)
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
  fi
}
add_to_path

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Open a new terminal, then run: clawpwn --help"
echo ""
