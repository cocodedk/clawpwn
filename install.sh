#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "=== ClawPwn Installer ==="
echo ""

# Get sudo upfront so we don't prompt multiple times
echo "This installer needs sudo for: installing scanners and setting permissions."
sudo -v || { echo "Error: sudo access required"; exit 1; }

# Keep sudo alive in background
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &

# Helpers
set_or_append_env_key() {
  local file="$1"
  local key="$2"
  local value="$3"

  touch "$file"
  if grep -qE "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf "%s=%s\n" "$key" "$value" >> "$file"
  fi
}

get_env_value() {
  local file="$1"
  local key="$2"
  if [ -f "$file" ]; then
    grep -E "^${key}=" "$file" | tail -n 1 | cut -d= -f2-
  fi
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# Ensure uv is installed
if ! command -v uv >/dev/null 2>&1; then
  echo "[1/8] Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
else
  echo "[1/8] uv already installed"
fi

# Ensure Rust/cargo is installed
if ! command -v cargo >/dev/null 2>&1; then
  echo "[2/8] Installing Rust (cargo)..."
  curl -LsSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain stable
else
  echo "[2/8] Rust already installed"
fi

# Ensure PATH includes cargo, local bin, and go bin
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
# Source cargo env if exists (for fresh installs)
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

# Install ClawPwn
echo "[3/8] Installing ClawPwn..."
uv tool install . --force --reinstall --refresh

# Install scanners
echo "[4/8] Installing scanners (nmap, masscan, rustscan, naabu)..."
# Note: naabu is installed in step 5 alongside other Go-based tools (needs Go)

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

# Verify scanners (naabu verified after Go-based installs in step 5)
for bin in nmap masscan rustscan; do
  if [ "$bin" = "rustscan" ] && [ -x "$HOME/.cargo/bin/rustscan" ]; then
    echo "  $bin: $HOME/.cargo/bin/rustscan"
  elif command -v "$bin" >/dev/null 2>&1; then
    echo "  $bin: $(command -v "$bin")"
  else
    echo "  $bin: NOT FOUND"
  fi
done

echo "[5/8] Installing web scanners (nuclei, feroxbuster, ffuf, hydra, nikto, searchsploit, sqlmap, testssl, wpscan, zap)..."

# Install web scanner packages via package manager.
# Each package is installed individually so one missing package doesn't block
# the rest (e.g. "exploitdb" doesn't exist on standard Ubuntu but "hydra" does).
_pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y "$@" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "$@" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y "$@" >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm "$@" >/dev/null 2>&1
  elif command -v brew >/dev/null 2>&1; then
    brew install "$@" >/dev/null 2>&1
  else
    return 1
  fi
}

for pkg in amass nikto hydra sqlmap ffuf feroxbuster testssl.sh zaproxy seclists wordlists; do
  _pkg_install "$pkg" || true
done
# exploitdb has different names across distros
_pkg_install exploitdb || _pkg_install exploit-database || true

# wpscan via gem (Ruby-based) — install Ruby first if missing
if ! command -v wpscan >/dev/null 2>&1; then
  if ! command -v gem >/dev/null 2>&1; then
    echo "  Installing Ruby for wpscan..."
    if command -v apt-get >/dev/null 2>&1; then
      sudo apt-get install -y ruby ruby-dev build-essential zlib1g-dev >/dev/null 2>&1
    elif command -v dnf >/dev/null 2>&1; then
      sudo dnf install -y ruby ruby-devel gcc make >/dev/null 2>&1
    elif command -v yum >/dev/null 2>&1; then
      sudo yum install -y ruby ruby-devel gcc make >/dev/null 2>&1
    elif command -v pacman >/dev/null 2>&1; then
      sudo pacman -S --noconfirm ruby base-devel >/dev/null 2>&1
    elif command -v brew >/dev/null 2>&1; then
      brew install ruby >/dev/null 2>&1
    fi
  fi
  if command -v gem >/dev/null 2>&1; then
    echo "  Installing wpscan via gem..."
    sudo gem install wpscan --no-document >/dev/null 2>&1 || true
  fi
fi

# testssl.sh fallback via git if package not available
if ! command -v testssl.sh >/dev/null 2>&1 && ! command -v testssl >/dev/null 2>&1; then
  echo "  Installing testssl.sh via git..."
  if [ ! -d "$HOME/.local/share/testssl.sh/.git" ]; then
    rm -rf "$HOME/.local/share/testssl.sh" 2>/dev/null || true
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$HOME/.local/share/testssl.sh" 2>&1 || true
  fi
  if [ -f "$HOME/.local/share/testssl.sh/testssl.sh" ]; then
    chmod +x "$HOME/.local/share/testssl.sh/testssl.sh"
    ln -sf "$HOME/.local/share/testssl.sh/testssl.sh" "$HOME/.local/bin/testssl.sh" 2>/dev/null || true
  fi
fi

# hydra fallback: build from source if package manager didn't provide it
if ! command -v hydra >/dev/null 2>&1; then
  echo "  Installing hydra from source..."
  _hydra_tmp="$(mktemp -d)"
  if git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra.git "$_hydra_tmp" >/dev/null 2>&1; then
    (cd "$_hydra_tmp" && ./configure >/dev/null 2>&1 && make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1 && sudo make install >/dev/null 2>&1) || true
  fi
  rm -rf "$_hydra_tmp"
fi

# nikto fallback: git clone + symlink (Perl script, no compilation needed)
if ! command -v nikto >/dev/null 2>&1; then
  echo "  Installing nikto via git..."
  if [ ! -d "$HOME/.local/share/nikto" ]; then
    git clone --depth 1 https://github.com/sullo/nikto.git "$HOME/.local/share/nikto" >/dev/null 2>&1 || true
  fi
  if [ -f "$HOME/.local/share/nikto/program/nikto.pl" ]; then
    ln -sf "$HOME/.local/share/nikto/program/nikto.pl" "$HOME/.local/bin/nikto" 2>/dev/null || true
    chmod +x "$HOME/.local/bin/nikto" 2>/dev/null || true
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
if ! command -v amass >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
  echo "  Installing amass via go install..."
  go install github.com/owasp-amass/amass/v4/...@master >/dev/null 2>&1 || true
fi
if ! command -v naabu >/dev/null 2>&1 && [ ! -x "$HOME/.local/bin/naabu" ] && [ ! -x "$HOME/go/bin/naabu" ]; then
  if command -v go >/dev/null 2>&1; then
    echo "  Installing naabu via go install..."
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest >/dev/null 2>&1 || true
  fi
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

# searchsploit fallback via git when package manager did not provide exploitdb
if ! command -v searchsploit >/dev/null 2>&1; then
  echo "  Installing searchsploit via git (this may take a minute — ~350 MB)..."
  if [ ! -d "$HOME/.local/share/exploitdb/.git" ]; then
    rm -rf "$HOME/.local/share/exploitdb" 2>/dev/null || true
    git clone --depth 1 --progress \
      https://gitlab.com/exploit-database/exploitdb.git "$HOME/.local/share/exploitdb" 2>&1 \
      || git clone --depth 1 --progress \
        https://github.com/offensive-security/exploitdb.git "$HOME/.local/share/exploitdb" 2>&1 \
      || true
  fi
  if [ -f "$HOME/.local/share/exploitdb/searchsploit" ]; then
    chmod +x "$HOME/.local/share/exploitdb/searchsploit"
    ln -sf "$HOME/.local/share/exploitdb/searchsploit" "$HOME/.local/bin/searchsploit" 2>/dev/null || true
    # Configure searchsploit rc file if not present
    if [ ! -f "$HOME/.searchsploit_rc" ]; then
      sed "s|/opt/exploitdb|$HOME/.local/share/exploitdb|g" \
        "$HOME/.local/share/exploitdb/.searchsploit_rc" > "$HOME/.searchsploit_rc" 2>/dev/null || true
    fi
  else
    echo "  WARNING: searchsploit not found after clone — exploitdb may have failed to download"
  fi
fi

# Update searchsploit database
if command -v searchsploit >/dev/null 2>&1; then
  echo "  Updating searchsploit database..."
  searchsploit -u >/dev/null 2>&1 || true
fi

# Verify naabu (port scanner installed via Go above)
if [ -x "$HOME/.local/bin/naabu" ]; then
  echo "  naabu: $HOME/.local/bin/naabu"
elif [ -x "$HOME/go/bin/naabu" ]; then
  echo "  naabu: $HOME/go/bin/naabu"
elif command -v naabu >/dev/null 2>&1; then
  echo "  naabu: $(command -v naabu)"
else
  echo "  naabu: NOT FOUND"
fi

# Verify web scanners — required tools error loudly, truly optional ones don't
_web_scanner_missing=()
for bin in amass nuclei feroxbuster ffuf hydra nikto searchsploit sqlmap testssl.sh wpscan; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "  $bin: $(command -v "$bin")"
  else
    echo "  $bin: NOT FOUND"
    _web_scanner_missing+=("$bin")
  fi
done
# docker is checked separately — truly optional for web scanning
if command -v docker >/dev/null 2>&1; then
  echo "  docker: $(command -v docker)"
else
  echo "  docker: NOT FOUND (optional — only needed for ZAP)"
fi
if [ "${#_web_scanner_missing[@]}" -gt 0 ]; then
  echo ""
  echo "  WARNING: ${#_web_scanner_missing[@]} scanner(s) failed to install: ${_web_scanner_missing[*]}"
  echo "  Some scan capabilities will be unavailable. Re-run install.sh or install manually."
fi

echo "  Ensuring credential wordlist availability..."

# Prefer native distro wordlists, then direct rockyou download to /tmp, then
# direct SecLists files, then fallback file.
cred_wordlist=""
wordlist_dir="$HOME/.local/share/clawpwn/wordlists"
mkdir -p "$wordlist_dir"

# On Kali/Debian, rockyou is commonly provided by the "wordlists" package.
if [ ! -f "/usr/share/wordlists/rockyou.txt" ] && [ ! -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "  Attempting to install Kali/Debian wordlists package..."
    sudo apt-get install -y wordlists >/dev/null 2>&1 || true
  fi
fi

if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
  cred_wordlist="/usr/share/wordlists/rockyou.txt"
fi

if [ -z "$cred_wordlist" ] && [ -f "/usr/share/wordlists/rockyou.txt.gz" ] && command -v gzip >/dev/null 2>&1; then
  gz_target="$wordlist_dir/rockyou.txt"
  if [ ! -s "$gz_target" ]; then
    gzip -dc "/usr/share/wordlists/rockyou.txt.gz" > "$gz_target" 2>/dev/null || true
  fi
  [ -s "$gz_target" ] && cred_wordlist="$gz_target"
fi

# Direct download fallback: use previously downloaded copy or fetch rockyou.txt.
if [ -z "$cred_wordlist" ]; then
  local_rockyou="$wordlist_dir/rockyou.txt"
  tmp_rockyou="/tmp/rockyou.txt"
  if [ -s "$local_rockyou" ]; then
    cred_wordlist="$local_rockyou"
  elif [ -s "$tmp_rockyou" ]; then
    cp -f "$tmp_rockyou" "$local_rockyou" 2>/dev/null || true
    cred_wordlist="$([ -s "$local_rockyou" ] && echo "$local_rockyou" || echo "$tmp_rockyou")"
  elif command -v wget >/dev/null 2>&1; then
    echo "  Downloading rockyou.txt..."
    wget -qO "$tmp_rockyou" "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt" >/dev/null 2>&1 || true
    if [ -s "$tmp_rockyou" ]; then
      cp -f "$tmp_rockyou" "$local_rockyou" 2>/dev/null || true
      cred_wordlist="$([ -s "$local_rockyou" ] && echo "$local_rockyou" || echo "$tmp_rockyou")"
    fi
  fi
fi

if [ -z "$cred_wordlist" ]; then
  for candidate in \
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt" \
    "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt" \
    "$HOME/.local/share/seclists/Passwords/Common-Credentials/10k-most-common.txt" \
    "$HOME/.local/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
  do
    if [ -f "$candidate" ]; then
      cred_wordlist="$candidate"
      break
    fi
  done
fi

if [ -z "$cred_wordlist" ]; then
  echo "  Fetching SecLists wordlist files..."
  _download_wordlist() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$url" -o "$dest" >/dev/null 2>&1 || return 1
    elif command -v wget >/dev/null 2>&1; then
      wget -qO "$dest" "$url" >/dev/null 2>&1 || return 1
    else
      return 1
    fi
    [ -s "$dest" ]
  }

  seclists_10k="$wordlist_dir/seclists-10k-most-common.txt"
  seclists_500="$wordlist_dir/seclists-500-worst-passwords.txt"

  _download_wordlist \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
    "$seclists_10k" && cred_wordlist="$seclists_10k"

  if [ -z "$cred_wordlist" ]; then
    _download_wordlist \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt" \
      "$seclists_500" && cred_wordlist="$seclists_500"
  fi
fi

if [ -z "$cred_wordlist" ]; then
  cred_wordlist="$wordlist_dir/clawpwn-default-passwords.txt"
  cat > "$cred_wordlist" <<'EOF'
password
admin
123456
12345
root
toor
guest
test
changeme
welcome
letmein
qwerty
admin123
password123
12345678
EOF
fi

set_or_append_env_key "$REPO_ROOT/.env" "CLAWPWN_CRED_WORDLIST" "$cred_wordlist"
echo "  credential wordlist: $cred_wordlist"

# Set up passwordless sudo for scanners (Linux only)
echo "[6/8] Setting up scanner permissions..."
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

echo "[7/8] Setting up centralized experience DB (Postgres + Docker Compose)..."

# Ensure Docker is installed
if ! command -v docker >/dev/null 2>&1; then
  echo "  Docker not found. Installing..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo apt-get install -y docker.io docker-compose-plugin >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y docker docker-compose-plugin >/dev/null 2>&1 \
      || sudo dnf install -y docker docker-compose >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y docker docker-compose-plugin >/dev/null 2>&1 \
      || sudo yum install -y docker docker-compose >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm docker docker-compose >/dev/null
  elif command -v brew >/dev/null 2>&1; then
    brew install --cask docker >/dev/null 2>&1 || brew install docker >/dev/null 2>&1
  fi
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker installation failed. Cannot continue."
  exit 1
fi

# Start Docker daemon when systemd is available
if [ "$(uname)" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
  sudo systemctl enable --now docker >/dev/null 2>&1 || true
fi

# Add user to docker group (takes effect on next login)
if [ "$(uname)" = "Linux" ] && getent group docker >/dev/null 2>&1; then
  sudo usermod -aG docker "$(whoami)" >/dev/null 2>&1 || true
fi

# Determine docker privilege mode
DOCKER_PREFIX=()
if docker info >/dev/null 2>&1; then
  DOCKER_PREFIX=()
elif sudo docker info >/dev/null 2>&1; then
  DOCKER_PREFIX=(sudo)
else
  echo "Error: Docker daemon is not reachable."
  exit 1
fi

# Determine compose command
COMPOSE_MODE=""
if "${DOCKER_PREFIX[@]}" docker compose version >/dev/null 2>&1; then
  COMPOSE_MODE="plugin"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_MODE="binary"
fi

if [ -z "$COMPOSE_MODE" ]; then
  echo "Error: Docker Compose is not available."
  exit 1
fi

compose_run() {
  if [ "$COMPOSE_MODE" = "plugin" ]; then
    "${DOCKER_PREFIX[@]}" docker compose -f "$REPO_ROOT/docker-compose.experience-db.yml" --env-file "$REPO_ROOT/.env.experience" "$@"
  else
    "${DOCKER_PREFIX[@]}" docker-compose -f "$REPO_ROOT/docker-compose.experience-db.yml" --env-file "$REPO_ROOT/.env.experience" "$@"
  fi
}

# Prepare centralized DB environment
experience_env="$REPO_ROOT/.env.experience"
db_name="$(get_env_value "$experience_env" "EXPERIENCE_DB_NAME")"
db_user="$(get_env_value "$experience_env" "EXPERIENCE_DB_USER")"
db_port="$(get_env_value "$experience_env" "EXPERIENCE_DB_PORT")"
db_password="$(get_env_value "$experience_env" "EXPERIENCE_DB_PASSWORD")"

[ -n "$db_name" ] || db_name="clawpwn_experience"
[ -n "$db_user" ] || db_user="clawpwn"
[ -n "$db_port" ] || db_port="54329"
[ -n "$db_password" ] || db_password="$(generate_secret)"

set_or_append_env_key "$experience_env" "EXPERIENCE_DB_NAME" "$db_name"
set_or_append_env_key "$experience_env" "EXPERIENCE_DB_USER" "$db_user"
set_or_append_env_key "$experience_env" "EXPERIENCE_DB_PORT" "$db_port"
set_or_append_env_key "$experience_env" "EXPERIENCE_DB_PASSWORD" "$db_password"

db_url="postgresql://${db_user}:${db_password}@127.0.0.1:${db_port}/${db_name}"
set_or_append_env_key "$experience_env" "CLAWPWN_EXPERIENCE_DB_URL" "$db_url"
set_or_append_env_key "$REPO_ROOT/.env" "CLAWPWN_EXPERIENCE_DB_URL" "$db_url"

# Ensure persistent volume exists (survives container recreation/removal)
"${DOCKER_PREFIX[@]}" docker volume inspect clawpwn_pgdata >/dev/null 2>&1 \
  || "${DOCKER_PREFIX[@]}" docker volume create clawpwn_pgdata >/dev/null

# Start service
mkdir -p "$REPO_ROOT/backups"
compose_run up -d experience-db >/dev/null

# Wait for healthy database
container_id="$(compose_run ps -q experience-db)"
if [ -z "$container_id" ]; then
  echo "Error: experience-db container not found after startup."
  exit 1
fi

attempts=0
max_attempts=60
while [ "$attempts" -lt "$max_attempts" ]; do
  status="$("${DOCKER_PREFIX[@]}" docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
  if [ "$status" = "healthy" ] || [ "$status" = "running" ]; then
    break
  fi
  attempts=$((attempts + 1))
  sleep 2
done

if [ "$attempts" -eq "$max_attempts" ]; then
  echo "Error: experience-db did not become healthy in time."
  compose_run logs --tail=50 experience-db || true
  exit 1
fi

# Apply schema/seed scripts on every install (works for fresh and existing volumes)
compose_run exec -T experience-db \
  psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/001_extensions.sql >/dev/null
compose_run exec -T experience-db \
  psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/010_experience_schema.sql >/dev/null
compose_run exec -T experience-db \
  psql -U "$db_user" -d "$db_name" -v ON_ERROR_STOP=1 \
  -f /docker-entrypoint-initdb.d/020_experience_seed.sql >/dev/null

seed_count="$(compose_run exec -T experience-db \
  psql -U "$db_user" -d "$db_name" -tAc \
  "SELECT count(*) FROM experiences WHERE tenant_id='default' AND fingerprint IN (
    'stateful_form_login_v1',
    'phpmyadmin_login_flow_v1',
    'phpmyadmin_setup_cve_2009_1151_v1',
    'credential_test_zero_attempts_diagnostic_v1'
  );" | tr -d '[:space:]')"

if [ "$seed_count" != "4" ]; then
  echo "Error: experience seed verification failed (expected 4, got ${seed_count:-0})."
  exit 1
fi

echo "  experience-db: healthy"
echo "  persistent volume: clawpwn_pgdata"
echo "  connection URL written to .env and .env.experience"
echo "  experience seeds installed: $seed_count"

echo "[8/8] Metasploitable2 lab target..."

# Check if msf2 is already running
msf2_running=false
if "${DOCKER_PREFIX[@]}" docker inspect --format '{{.State.Running}}' msf2 2>/dev/null | grep -q true; then
  msf2_running=true
fi

if $msf2_running; then
  echo "  msf2 container already running."
  msf2_id="$("${DOCKER_PREFIX[@]}" docker inspect --format '{{.ID}}' msf2 2>/dev/null)"
else
  echo ""
  echo "  Metasploitable2 is a vulnerable VM used as a practice target (~800 MB Docker image)."
  printf "  Do you want to pull and start it? [Y/n] "
  read -r msf2_answer </dev/tty 2>/dev/null || msf2_answer="y"
  msf2_answer="${msf2_answer:-y}"
  if [[ ! "$msf2_answer" =~ ^[Yy] ]]; then
    echo "  Skipping Metasploitable2. You can start it later with: ./start-lab.sh"
    msf2_id=""
  else
    # Remove stopped container with the same name before starting fresh
    "${DOCKER_PREFIX[@]}" docker rm -f msf2 >/dev/null 2>&1 || true
    echo "  Pulling and starting msf2 (this may take a few minutes on first run)..."
    compose_run pull msf2 2>&1 | grep -E 'Pull|Download|Extracting|Status|Digest' || true
    compose_run up -d msf2
    msf2_id="$(compose_run ps -q msf2 2>/dev/null || true)"
    if [ -z "$msf2_id" ]; then
      echo "  WARNING: msf2 container failed to start. Check: docker compose logs msf2"
    fi
  fi
fi

if [ -n "$msf2_id" ]; then
  # Wait for core services (SSH as indicator)
  echo "  Waiting for services to initialize..."
  msf2_wait=0
  msf2_max_wait=60
  while [ "$msf2_wait" -lt "$msf2_max_wait" ]; do
    if "${DOCKER_PREFIX[@]}" docker exec msf2 nc -z 127.0.0.1 22 2>/dev/null; then
      break
    fi
    msf2_wait=$((msf2_wait + 2))
    sleep 2
  done

  if [ "$msf2_wait" -ge "$msf2_max_wait" ]; then
    echo "  Warning: Metasploitable2 services did not initialize in ${msf2_max_wait}s."
  else
    echo "  Core services ready (${msf2_wait}s)."
  fi

  # Settle time for Java/Tomcat
  sleep 5

  # Check ports and restart down services
  msf2_ports=(21 22 23 25 80 111 139 445 512 513 514 1099 1524 2121 3306 3632 5432 5900 6000 6667 6697 8009 8180 8787)

  msf2_port_to_service() {
    case "$1" in
      21|23|512|513|514|1524) echo "xinetd" ;;
      22) echo "ssh" ;;
      25) echo "postfix" ;;
      80) echo "apache2" ;;
      111) echo "portmap" ;;
      139|445) echo "samba" ;;
      2121) echo "proftpd" ;;
      3306) echo "mysql" ;;
      3632) echo "distcc" ;;
      5432) echo "postgresql-8.3" ;;
      8009|8180) echo "tomcat5.5" ;;
      *) echo "" ;;
    esac
  }

  msf2_down_ports=()
  for p in "${msf2_ports[@]}"; do
    if ! "${DOCKER_PREFIX[@]}" docker exec msf2 nc -z 127.0.0.1 "$p" 2>/dev/null; then
      msf2_down_ports+=("$p")
    fi
  done

  if [ "${#msf2_down_ports[@]}" -gt 0 ]; then
    echo "  Restarting services for ${#msf2_down_ports[@]} closed port(s)..."
    msf2_restarted=()
    for p in "${msf2_down_ports[@]}"; do
      svc="$(msf2_port_to_service "$p")"
      if [ -n "$svc" ]; then
        skip=false
        for s in "${msf2_restarted[@]+"${msf2_restarted[@]}"}"; do
          [ "$s" = "$svc" ] && skip=true
        done
        if ! $skip; then
          "${DOCKER_PREFIX[@]}" docker exec msf2 service "$svc" restart >/dev/null 2>&1 || true
          msf2_restarted+=("$svc")
        fi
      fi
    done
    sleep 5
  fi

  # Final count
  msf2_open=0
  for p in "${msf2_ports[@]}"; do
    if "${DOCKER_PREFIX[@]}" docker exec msf2 nc -z 127.0.0.1 "$p" 2>/dev/null; then
      msf2_open=$((msf2_open + 1))
    fi
  done

  echo "  msf2: ${msf2_open}/${#msf2_ports[@]} services listening"

  # Detect container IP on the Docker bridge network
  msf2_ip="$("${DOCKER_PREFIX[@]}" docker inspect msf2 \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"
  if [ -n "$msf2_ip" ]; then
    echo "  msf2 IP: $msf2_ip"
    set_or_append_env_key "$REPO_ROOT/.env" "CLAWPWN_LAB_TARGET" "$msf2_ip"
  else
    echo "  WARNING: could not determine msf2 container IP"
  fi
  echo "  container: msf2 (manual start only — use ./install.sh or ./start-lab.sh)"
fi

# Add PATH to shell profile if not already there
add_to_path() {
  local profile=""
  local is_fish=false

  # Detect shell using basename so we match regardless of install prefix
  # (/usr/bin/fish, /usr/local/bin/fish, /opt/homebrew/bin/fish, etc.)
  local shell_name
  shell_name="$(basename "${SHELL:-bash}")"

  case "$shell_name" in
    fish)
      profile="$HOME/.config/fish/config.fish"
      is_fish=true
      mkdir -p "$HOME/.config/fish"
      ;;
    zsh)
      profile="$HOME/.zshrc"
      ;;
    bash)
      profile="$HOME/.bashrc"
      ;;
    *)
      if [ -f "$HOME/.profile" ]; then
        profile="$HOME/.profile"
      fi
      ;;
  esac

  if [ -z "$profile" ]; then
    echo "  Could not detect shell profile. Add these directories to your PATH manually:"
    echo "    $HOME/.cargo/bin  $HOME/.local/bin  $HOME/go/bin"
    return
  fi

  # Use our own marker so Rust-installer's .cargo/bin entry doesn't cause us
  # to skip adding .local/bin and go/bin.
  if grep -qF '# ClawPwn PATH' "$profile" 2>/dev/null; then
    echo "  PATH already configured in $profile"
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
    return
  fi

  echo "" >> "$profile"
  echo "# ClawPwn PATH" >> "$profile"

  if $is_fish; then
    # fish_add_path is idempotent (won't duplicate) — available since fish 3.2
    echo 'fish_add_path -g $HOME/.cargo/bin $HOME/.local/bin $HOME/go/bin' >> "$profile"
    # Source Rust env for fish if available (provides cargo, rustc, etc.)
    if [ -f "$HOME/.cargo/env.fish" ]; then
      echo 'test -f $HOME/.cargo/env.fish; and source $HOME/.cargo/env.fish' >> "$profile"
    fi
  else
    echo 'export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"' >> "$profile"
  fi

  echo "  Added PATH to $profile"
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/go/bin:$PATH"
}
add_to_path

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Open a new terminal, then run: clawpwn --help"
echo ""
