#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[manage]${NC} $*"; }
warn() { echo -e "${YELLOW}[manage]${NC} $*"; }
die()  { echo -e "${RED}[manage] ERROR:${NC} $*" >&2; exit 1; }

check_deps() {
  command -v docker >/dev/null 2>&1 || die "Docker is not installed."
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is not installed."
}

cmd_install() {
  check_deps

  log "Checking prerequisites..."

  # Create data directory for abuse-detection.db
  if [ ! -d "./data" ]; then
    mkdir -p ./data
    log "Created ./data directory"
  fi

  # Ensure .env exists
  if [ ! -f "./.env" ]; then
    if [ -f "./.env.example" ]; then
      cp .env.example .env
      warn ".env not found - copied from .env.example"
      warn "Please edit .env with your configuration before continuing."
      warn "At minimum set: SERVER_HOST_NAME, SSL_CERT_PATH, SSL_KEY_PATH"
      exit 1
    else
      die ".env not found and no .env.example to copy from."
    fi
  fi

  # Check required vars
  # shellcheck disable=SC1091
  source <(grep -v '^#' .env | grep -v '^$' | sed 's/^/export /')
  if [ -z "${SERVER_HOST_NAME:-}" ]; then
    die "SERVER_HOST_NAME is not set in .env - required for Caddy SSL."
  fi
  if [ -z "${SSL_CERT_PATH:-}" ] || [ ! -f "${SSL_CERT_PATH}" ]; then
    die "SSL_CERT_PATH is not set or file does not exist: ${SSL_CERT_PATH:-unset}"
  fi
  if [ -z "${SSL_KEY_PATH:-}" ] || [ ! -f "${SSL_KEY_PATH}" ]; then
    die "SSL_KEY_PATH is not set or file does not exist: ${SSL_KEY_PATH:-unset}"
  fi

  log "Building and starting containers..."
  docker compose up -d --build

  log ""
  log "✓ MeshCore MQTT Broker is running"
  log "  WebSocket: wss://${SERVER_HOST_NAME}"
  log "  Logs:      ./manage.sh logs"
}

cmd_update() {
  cmd_install
}

cmd_logs() {
  check_deps
  docker compose logs -f broker
}

cmd_stop() {
  check_deps
  docker compose stop
  log "✓ Stopped"
}

cmd_start() {
  check_deps
  docker compose start
  log "✓ Started"
}

cmd_restart() {
  check_deps
  docker compose restart
  log "✓ Restarted"
}

cmd_status() {
  check_deps
  docker compose ps
}

cmd_help() {
  echo "Usage: ./manage.sh <command>"
  echo ""
  echo "Commands:"
  echo "  install    Set up and start everything (safe to re-run after code or .env changes)"
  echo "  update     Alias for install"
  echo "  logs       Tail broker logs"
  echo "  start      Start stopped containers"
  echo "  stop       Stop running containers"
  echo "  restart    Restart containers"
  echo "  status     Show container status"
}

case "${1:-help}" in
  install) cmd_install ;;
  update)  cmd_update ;;
  logs)    cmd_logs ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_restart ;;
  status)  cmd_status ;;
  *)       cmd_help ;;
esac
