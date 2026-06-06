#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

DEPLOY_TARGET_DIR="${DEPLOY_TARGET_DIR:-/opt/oadtd}"
DEPLOY_SERVICE="${DEPLOY_SERVICE:-oadtd}"
DEPLOY_READY_PATH="${DEPLOY_READY_PATH:-/readyz}"
DEPLOY_SOURCE_DIR="${DEPLOY_SOURCE_DIR:-dist}"
DEPLOY_RELEASE_ID="${DEPLOY_RELEASE_ID:-manual-$(date +%Y%m%d%H%M%S)}"
DEPLOY_HTTP_BASE="${DEPLOY_HTTP_BASE:-http://127.0.0.1:8080}"
DEPLOY_WAIT_SECONDS="${DEPLOY_WAIT_SECONDS:-30}"
DEPLOY_WAIT_INTERVAL="${DEPLOY_WAIT_INTERVAL:-1}"

log() {
  printf '[deploy] %s\n' "$*"
}

group_start() {
  printf '::group::%s\n' "$*"
}

group_end() {
  printf '::endgroup::\n'
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "This helper must run as root or via sudo."
    exit 1
  fi
}

diagnostics() {
  log "Diagnostics:"
  log "  target_dir=$DEPLOY_TARGET_DIR"
  log "  source_dir=$DEPLOY_SOURCE_DIR"
  log "  release_id=$DEPLOY_RELEASE_ID"
  log "  service=$DEPLOY_SERVICE"
  log "  ready_path=$DEPLOY_READY_PATH"
  log "  current=$(readlink -f "$DEPLOY_TARGET_DIR/current" 2>/dev/null || true)"

  group_start "target tree"
  ls -la "$DEPLOY_TARGET_DIR" 2>/dev/null || true
  ls -la "$DEPLOY_TARGET_DIR/releases" 2>/dev/null || true
  group_end

  group_start "service status"
  systemctl status "$DEPLOY_SERVICE" --no-pager -l || true
  group_end

  group_start "recent journal"
  journalctl -u "$DEPLOY_SERVICE" -n 100 --no-pager || true
  group_end
}

rollback_release() {
  if [ -n "${PREVIOUS_RELEASE:-}" ] && [ -d "$PREVIOUS_RELEASE" ]; then
    log "Rolling back to $PREVIOUS_RELEASE"
    ln -sfn "$PREVIOUS_RELEASE" "$DEPLOY_TARGET_DIR/current"
    systemctl restart "$DEPLOY_SERVICE" || true
  fi
}

on_error() {
  local code="$1"
  local line="$2"
  log "FAILED at line $line with exit code $code"
  rollback_release
  diagnostics
  exit "$code"
}

trap 'on_error $? $LINENO' ERR

require_root

if [ ! -d "$DEPLOY_SOURCE_DIR" ]; then
  log "Source directory not found: $DEPLOY_SOURCE_DIR"
  exit 1
fi

if [ ! -x "$DEPLOY_SOURCE_DIR/oadtd" ] || [ ! -x "$DEPLOY_SOURCE_DIR/oadtdctl" ]; then
  log "Missing binaries in $DEPLOY_SOURCE_DIR"
  ls -la "$DEPLOY_SOURCE_DIR" || true
  exit 1
fi

CURRENT_LINK="$DEPLOY_TARGET_DIR/current"
RELEASE_DIR="$DEPLOY_TARGET_DIR/releases/$DEPLOY_RELEASE_ID"
PREVIOUS_RELEASE=""

if [ -L "$CURRENT_LINK" ] || [ -e "$CURRENT_LINK" ]; then
  PREVIOUS_RELEASE="$(readlink -f "$CURRENT_LINK" || true)"
fi

group_start "prepare target"
install -d -m 0755 "$DEPLOY_TARGET_DIR"
install -d -m 0755 "$DEPLOY_TARGET_DIR/releases"
rm -rf "$RELEASE_DIR"
install -d -m 0755 "$RELEASE_DIR"
group_end

group_start "install release"
install -m 0755 "$DEPLOY_SOURCE_DIR/oadtd" "$RELEASE_DIR/oadtd"
install -m 0755 "$DEPLOY_SOURCE_DIR/oadtdctl" "$RELEASE_DIR/oadtdctl"
chown -R root:root "$RELEASE_DIR"
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK"
group_end

group_start "restart service"
systemctl restart "$DEPLOY_SERVICE"
group_end

group_start "wait for readiness"
ready_ok=0
for _ in $(seq 1 "$DEPLOY_WAIT_SECONDS"); do
  if curl -fsS "$DEPLOY_HTTP_BASE$DEPLOY_READY_PATH" >/dev/null; then
    ready_ok=1
    break
  fi
  sleep "$DEPLOY_WAIT_INTERVAL"
done
group_end

if [ "$ready_ok" -ne 1 ]; then
  log "Readiness check failed for $DEPLOY_SERVICE"
  rollback_release
  diagnostics
  exit 1
fi

group_start "final status"
systemctl --no-pager -l status "$DEPLOY_SERVICE" || true
curl -fsS "$DEPLOY_HTTP_BASE$DEPLOY_READY_PATH"
group_end

log "Deploy complete: $RELEASE_DIR"
