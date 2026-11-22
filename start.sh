#!/usr/bin/env bash
set -euo pipefail

# ---------- paths and constants ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${HOME}/.config/lc-server"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DATA_DIR="${SCRIPT_DIR}/data"
LC_UID_GID="10001:10001"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# ---------- colors ----------
if [[ -t 1 ]]; then
  R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
else
  R=''; G=''; Y=''; B=''; N=''
fi
info()  { echo -e "${B}[*]${N} $*"; }
ok()    { echo -e "${G}[+]${N} $*"; }
warn()  { echo -e "${Y}[!]${N} $*"; }
err()   { echo -e "${R}[-]${N} $*" >&2; }
die()   { err "$*"; exit 1; }

# ---------- environment checks ----------
check_deps() {
  command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
  docker compose version >/dev/null 2>&1 || die "docker compose plugin not found"
  [[ -f "$COMPOSE_FILE" ]] || die "$COMPOSE_FILE not found — run from the repository root"
}

# ---------- config template ----------
write_default_config() {
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_FILE" <<'EOF'
[server]
relay_addr = "0.0.0.0:8080"
files_addr = "0.0.0.0:8081"
max_body_bytes = 65664
max_file_bytes = 1073741824
pull_timeout_sec = 25
relay_pull_max_concurrent = 256

[security]
guard_header_name = "X-Custom-Guard"
guard_header_value = "change-me"
timestamp_skew_sec = 60
nonce_ttl_sec = 120

[storage]
db_path = "/var/lib/lc-server/relay.db"
files_dir = "/var/lib/lc-server/files"
message_ttl_hours = 72
file_ttl_hours = 168
EOF
  chmod 600 "$CONFIG_FILE"
}

ensure_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    ok "config exists: $CONFIG_FILE"
    return 0
  fi
  info "config not found — creating template at $CONFIG_FILE"
  write_default_config
  ok "created $CONFIG_FILE (mode 600)"
  warn "don't forget to change guard_header_value: ./start.sh config"
}

# ---------- data ----------
ensure_data() {
  mkdir -p "$DATA_DIR"
  if ! chown -R "$LC_UID_GID" "$DATA_DIR" 2>/dev/null; then
    die "failed to chown $DATA_DIR — run: sudo chown -R $LC_UID_GID $DATA_DIR"
  fi
  ok "data: $DATA_DIR (owner $LC_UID_GID)"
}

# ---------- health wait ----------
wait_healthy() {
  local timeout="${1:-90}" elapsed=0 status
  info "waiting for healthy (timeout ${timeout}s)..."
  while (( elapsed < timeout )); do
    status=$(docker inspect lc-server --format='{{.State.Health.Status}}' 2>/dev/null || echo "missing")
    case "$status" in
      healthy)
        ok "lc-server healthy"
        return 0 ;;
      unhealthy)
        err "lc-server unhealthy — last logs:"
        docker logs lc-server --tail 30 || true
        return 1 ;;
    esac
    sleep 2; ((elapsed+=2))
  done
  err "timeout waiting for healthy (${timeout}s)"
  docker logs lc-server --tail 30 || true
  return 1
}

# ---------- commands ----------
cmd_up() {
  check_deps
  ensure_config
  ensure_data
  info "docker compose up -d --remove-orphans"
  docker compose up -d --remove-orphans
  wait_healthy 90
  ok "stack is up"
  echo
  docker compose ps
}

cmd_config() {
  ensure_config
  local editor="${EDITOR:-}"
  if [[ -z "$editor" ]]; then
    for e in nano vim vi; do command -v "$e" >/dev/null 2>&1 && { editor="$e"; break; }; done
  fi
  [[ -n "$editor" ]] || die "no editor found (nano/vim/vi) — set \$EDITOR"
  info "opening $CONFIG_FILE in $editor"
  "$editor" "$CONFIG_FILE"
  ok "config saved"
  if docker inspect lc-server >/dev/null 2>&1; then
    warn "changes will take effect after: ./start.sh restart"
  fi
}

cmd_restart() {
  check_deps
  docker compose restart lc-server
  wait_healthy 60
}

cmd_logs()   { check_deps; docker compose logs -f "${@:-}"; }
cmd_health() {
  check_deps
  local s; s=$(docker inspect lc-server --format='{{.State.Health.Status}}' 2>/dev/null || echo "missing")
  echo "lc-server: $s"
  docker compose ps
}
cmd_down()   { check_deps; docker compose down; ok "stack stopped"; }
cmd_status() { check_deps; docker compose ps; }

usage() {
  cat <<EOF
usage: $0 <command>

  up        idempotent start: config (if missing) → data → compose up → wait healthy
  config    create template (if missing) and open it in \$EDITOR
  restart   restart lc-server and wait for healthy
  logs      docker compose logs -f
  health    healthcheck status + compose ps
  status    docker compose ps
  down      stop the stack
EOF
}

case "${1:-up}" in
  up)      cmd_up ;;
  config)  cmd_config ;;
  restart) cmd_restart ;;
  logs)    shift; cmd_logs "$@" ;;
  health)  cmd_health ;;
  status)  cmd_status ;;
  down)    cmd_down ;;
  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
