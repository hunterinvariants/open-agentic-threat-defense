#!/usr/bin/env bash
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

INSTANCES=()
if [ "$#" -gt 0 ]; then
  INSTANCES=("$@")
elif [ -n "${OATD_HA_INSTANCES:-}" ]; then
  IFS=',' read -r -a INSTANCES <<<"${OATD_HA_INSTANCES}"
else
  INSTANCES=("blue" "green")
fi

READY_TIMEOUT="${OATD_HA_READY_TIMEOUT:-60}"
READY_INTERVAL="${OATD_HA_READY_INTERVAL:-2}"
SERVICE_NAME="${OATD_HA_SERVICE_NAME:-oadtd}"
ENV_DIR="${OATD_HA_ENV_DIR:-/etc/oadtd}"

log() {
  printf '[ha-rollout] %s\n' "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "Run as root or via sudo."
    exit 1
  fi
}

wait_ready() {
  local addr="$1"
  local url="http://${addr}/readyz"
  local attempt=1
  while [ "$attempt" -le "$READY_TIMEOUT" ]; do
    if curl -fsS "$url" >/dev/null; then
      return 0
    fi
    sleep "$READY_INTERVAL"
    attempt=$((attempt + 1))
  done
  return 1
}

require_root

for instance in "${INSTANCES[@]}"; do
  instance="$(printf '%s' "$instance" | tr -d '[:space:]')"
  if [ -z "$instance" ]; then
    continue
  fi
  env_file="${ENV_DIR}/${instance}.env"
  if [ ! -f "$env_file" ]; then
    log "Missing env file: $env_file"
    exit 1
  fi
  log "Reloading $instance from $env_file"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
  addr="${OATD_ADDR:-127.0.0.1:8080}"
  log "Restarting ${SERVICE_NAME}@${instance}"
  systemctl restart "${SERVICE_NAME}@${instance}"
  log "Waiting for ${addr}/readyz"
  if ! wait_ready "$addr"; then
    log "Instance ${instance} failed readiness"
    systemctl status "${SERVICE_NAME}@${instance}" --no-pager -l || true
    journalctl -u "${SERVICE_NAME}@${instance}" -n 100 --no-pager || true
    exit 1
  fi
  log "Instance ${instance} ready"
done

log "Rolling update complete"
