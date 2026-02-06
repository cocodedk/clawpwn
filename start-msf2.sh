#!/usr/bin/env bash
# start-msf2.sh — Start the Metasploitable2 container with all services verified.
# Usage: ./start-msf2.sh [--restart]
set -euo pipefail

RESTART=false
for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=true ;;
    -h|--help)
      echo "Usage: $0 [--restart]"
      echo "  --restart  Force-remove and recreate the container from scratch"
      exit 0
      ;;
    *) echo "Unknown option: $arg (try --help)"; exit 1 ;;
  esac
done

CONTAINER="msf2"
IMAGE="tleemcjr/metasploitable2"

# All Metasploitable2 service ports and their init.d service names
PORTS=(
  21 22 23 25 80 111 139 445
  512 513 514 1099 1524 2121 3306 3632
  5432 5900 6000 6667 6697 8009 8180 8787
)

declare -A PORT_LABELS=(
  [21]="FTP"       [22]="SSH"       [23]="Telnet"     [25]="SMTP"
  [80]="HTTP"      [111]="RPCbind"  [139]="NetBIOS"   [445]="SMB"
  [512]="rexec"    [513]="rlogin"   [514]="rsh"       [1099]="Java RMI"
  [1524]="Backdoor" [2121]="FTP-alt" [3306]="MySQL"   [3632]="distccd"
  [5432]="PostgreSQL" [5900]="VNC"  [6000]="X11"      [6667]="IRC"
  [6697]="IRC-SSL" [8009]="AJP"     [8180]="Tomcat"   [8787]="Ruby DRb"
)

# Map ports to the service that should be restarted if the port is down
declare -A PORT_SERVICE=(
  [21]="xinetd"    [22]="ssh"          [23]="xinetd"     [25]="postfix"
  [80]="apache2"   [111]="portmap"     [139]="samba"     [445]="samba"
  [512]="xinetd"   [513]="xinetd"      [514]="xinetd"    [1099]=""
  [1524]="xinetd"  [2121]="proftpd"    [3306]="mysql"    [3632]="distcc"
  [5432]="postgresql-8.3" [5900]=""    [6000]=""          [6667]=""
  [6697]=""        [8009]="tomcat5.5"  [8180]="tomcat5.5" [8787]=""
)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

# ── Build -p flags ───────────────────────────────────────────────────
port_flags=""
for p in "${PORTS[@]}"; do
  port_flags+=" -p ${p}:${p}"
done

# ── Container lifecycle ──────────────────────────────────────────────
if $RESTART; then
  info "Restart requested — tearing down container..."
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
fi

state=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "missing")

case "$state" in
  running)
    ok "Container '$CONTAINER' is already running."
    ;;
  exited|created)
    info "Container '$CONTAINER' exists but is stopped. Removing and recreating..."
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    info "Creating container with all ${#PORTS[@]} ports mapped..."
    # shellcheck disable=SC2086
    docker run -d -it --name "$CONTAINER" $port_flags "$IMAGE" >/dev/null
    ok "Container '$CONTAINER' started."
    ;;
  missing)
    info "Container '$CONTAINER' not found. Pulling image if needed..."
    # shellcheck disable=SC2086
    docker run -d -it --name "$CONTAINER" $port_flags "$IMAGE" >/dev/null
    ok "Container '$CONTAINER' created and started."
    ;;
  *)
    warn "Container in unexpected state ($state). Recreating..."
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    # shellcheck disable=SC2086
    docker run -d -it --name "$CONTAINER" $port_flags "$IMAGE" >/dev/null
    ok "Container '$CONTAINER' recreated."
    ;;
esac

# ── Wait for services.sh to finish ───────────────────────────────────
info "Waiting for services to initialize..."

MAX_WAIT=60
elapsed=0
while [ $elapsed -lt $MAX_WAIT ]; do
  if docker exec "$CONTAINER" nc -z 127.0.0.1 22 2>/dev/null; then
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done

if [ $elapsed -ge $MAX_WAIT ]; then
  warn "Timed out waiting for core services."
else
  ok "Core services ready (${elapsed}s)."
fi

# Settle time for Java/Tomcat
sleep 5

# ── Check & restart any down services ────────────────────────────────
check_port() {
  docker exec "$CONTAINER" nc -z 127.0.0.1 "$1" 2>/dev/null
}

restarted_services=()
restart_service() {
  local svc="$1"
  # Avoid restarting the same service twice
  for s in "${restarted_services[@]+"${restarted_services[@]}"}"; do
    [[ "$s" == "$svc" ]] && return
  done
  docker exec "$CONTAINER" service "$svc" restart >/dev/null 2>&1 || true
  restarted_services+=("$svc")
}

down_ports=()
for p in "${PORTS[@]}"; do
  if ! check_port "$p"; then
    down_ports+=("$p")
  fi
done

if [ ${#down_ports[@]} -gt 0 ]; then
  info "Restarting services for ${#down_ports[@]} closed port(s)..."
  for p in "${down_ports[@]}"; do
    svc="${PORT_SERVICE[$p]:-}"
    if [ -n "$svc" ]; then
      restart_service "$svc"
    fi
  done
  # Let restarted services bind
  sleep 5
fi

# ── Final verification ───────────────────────────────────────────────
info "Verifying all ${#PORTS[@]} services..."
echo ""

open_count=0
closed_count=0
closed_list=()

for p in "${PORTS[@]}"; do
  label="${PORT_LABELS[$p]:-unknown}"
  if check_port "$p"; then
    ok "$(printf '%-5s %-12s — open' "$p" "$label")"
    open_count=$((open_count + 1))
  else
    fail "$(printf '%-5s %-12s — not listening' "$p" "$label")"
    closed_count=$((closed_count + 1))
    closed_list+=("${p}/${label}")
  fi
done

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}Open: ${open_count}${NC}  |  ${RED}Closed: ${closed_count}${NC}  |  Total: ${#PORTS[@]}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [ $closed_count -gt 0 ]; then
  warn "Still closed: ${closed_list[*]}"
else
  ok "All services are up!"
fi

echo ""
ok "${BOLD}Metasploitable2 is ready at 127.0.0.1${NC}"
