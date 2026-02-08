#!/usr/bin/env bash
# start-lab.sh — Start Postgres experience DB and Metasploitable2 only if needed.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

POSTGRES_SERVICE="experience-db"
POSTGRES_CONTAINER="clawpwn-experience-db"
POSTGRES_ENV_FILE="$ROOT_DIR/.env.experience"
MSF2_CONTAINER="msf2"
MSF2_SCRIPT="$ROOT_DIR/start-msf2.sh"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

info() { echo -e "${CYAN}[*]${NC} $*"; }
ok() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }

DOCKER_PREFIX=()
if docker info >/dev/null 2>&1; then
  DOCKER_PREFIX=()
elif sudo docker info >/dev/null 2>&1; then
  DOCKER_PREFIX=(sudo)
else
  fail "Docker daemon is not reachable."
  exit 1
fi

COMPOSE_MODE=""
if "${DOCKER_PREFIX[@]}" docker compose version >/dev/null 2>&1; then
  COMPOSE_MODE="plugin"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_MODE="binary"
else
  fail "Docker Compose is not available."
  exit 1
fi

compose_run() {
  if [ "$COMPOSE_MODE" = "plugin" ]; then
    "${DOCKER_PREFIX[@]}" docker compose \
      -f "$ROOT_DIR/docker-compose.experience-db.yml" \
      --env-file "$POSTGRES_ENV_FILE" \
      "$@"
  else
    "${DOCKER_PREFIX[@]}" docker-compose \
      -f "$ROOT_DIR/docker-compose.experience-db.yml" \
      --env-file "$POSTGRES_ENV_FILE" \
      "$@"
  fi
}

start_postgres_if_needed() {
  local state
  state="$("${DOCKER_PREFIX[@]}" docker inspect -f '{{.State.Status}}' "$POSTGRES_CONTAINER" 2>/dev/null || echo "missing")"

  if [ "$state" = "running" ]; then
    ok "Postgres container '$POSTGRES_CONTAINER' is already running."
    return
  fi

  if [ ! -f "$POSTGRES_ENV_FILE" ]; then
    fail "Missing .env.experience. Run ./install.sh once first."
    exit 1
  fi

  info "Starting Postgres container '$POSTGRES_CONTAINER'..."
  mkdir -p "$ROOT_DIR/backups"

  "${DOCKER_PREFIX[@]}" docker volume inspect clawpwn_pgdata >/dev/null 2>&1 \
    || "${DOCKER_PREFIX[@]}" docker volume create clawpwn_pgdata >/dev/null

  compose_run up -d "$POSTGRES_SERVICE" >/dev/null
  ok "Postgres container started."
}

start_msf2_if_needed() {
  local state
  state="$("${DOCKER_PREFIX[@]}" docker inspect -f '{{.State.Status}}' "$MSF2_CONTAINER" 2>/dev/null || echo "missing")"

  if [ "$state" = "running" ]; then
    ok "Metasploitable2 container '$MSF2_CONTAINER' is already running."
    return
  fi

  if [ ! -x "$MSF2_SCRIPT" ]; then
    fail "Missing executable script: $MSF2_SCRIPT"
    exit 1
  fi

  info "Starting Metasploitable2 container '$MSF2_CONTAINER'..."
  if [ "${#DOCKER_PREFIX[@]}" -gt 0 ]; then
    "${DOCKER_PREFIX[@]}" "$MSF2_SCRIPT"
  else
    "$MSF2_SCRIPT"
  fi
}

start_postgres_if_needed
start_msf2_if_needed

ok "Lab containers are ready."
