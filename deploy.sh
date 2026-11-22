#!/usr/bin/env bash
#
# Cross-compile lc-server, copy the binary to a remote host, then rebuild and
# restart the Docker Compose stack there.
#
# Required:
#   HOST=relay.example.com
#
# Optional:
#   REMOTE_USER=deploy          (default: current $USER)
#   REMOTE_DIR=/opt/lastchance-server
#   ARCH=amd64                  (arm64 for ARM VPS)
#   WEAK_VPS=1                  (GOMAXPROCS=1 go build -p 1)
#
# The remote directory must already contain docker-compose.yml, Caddyfile and
# the rest of the deployment files. The config is installed from
# deploy/config.toml only when ~/.config/lc-server/config.toml is absent.

set -euo pipefail

: "${HOST:?set HOST, for example HOST=relay.example.com}"
REMOTE_USER="${REMOTE_USER:-${USER:-}}"
: "${REMOTE_USER:?set REMOTE_USER (could not infer the current user)}"
REMOTE_DIR="${REMOTE_DIR:-/opt/lastchance-server}"
ARCH="${ARCH:-amd64}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

mkdir -p bin

echo "==> building lc-server for linux/$ARCH"
if [ "${WEAK_VPS:-0}" = "1" ]; then
	CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOMAXPROCS=1 \
		go build -p 1 -trimpath -ldflags="-s -w" -o bin/lc-server ./cmd/lc-server
else
	CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
		go build -trimpath -ldflags="-s -w" -o bin/lc-server ./cmd/lc-server
fi

./bin/lc-server --version

SSH_TARGET="${REMOTE_USER}@${HOST}"

echo "==> preparing remote directories on ${SSH_TARGET}"
ssh "$SSH_TARGET" "mkdir -p '$REMOTE_DIR/bin' '$REMOTE_DIR/data' ~/.config/lc-server"

if ! ssh "$SSH_TARGET" "test -f '$REMOTE_DIR/docker-compose.yml'"; then
	echo "error: $REMOTE_DIR/docker-compose.yml is missing on the remote host" >&2
	exit 1
fi

echo "==> copying binary"
scp bin/lc-server "$SSH_TARGET:$REMOTE_DIR/bin/lc-server"

if ! ssh "$SSH_TARGET" "test -f ~/.config/lc-server/config.toml"; then
	echo "==> installing container config (first run)"
	scp deploy/config.toml "$SSH_TARGET:.config/lc-server/config.toml"
fi

# The container runs as uid/gid 10001. A bind-mounted ./data directory owned by
# the deploy user is not writable unless ownership is adjusted.
if ! ssh "$SSH_TARGET" "chown -R 10001:10001 '$REMOTE_DIR/data'" 2>/dev/null; then
	echo "warning: could not chown $REMOTE_DIR/data to 10001:10001;" >&2
	echo "         run on the server: sudo chown -R 10001:10001 $REMOTE_DIR/data" >&2
fi

echo "==> rebuilding and restarting the stack"
ssh "$SSH_TARGET" "cd '$REMOTE_DIR' && docker compose up -d --build"

echo "==> done"
