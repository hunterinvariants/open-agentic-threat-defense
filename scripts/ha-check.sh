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

ENV_DIR="${OATD_HA_ENV_DIR:-/etc/oadtd}"

log() {
  printf '[ha-check] %s\n' "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "Run as root or via sudo."
    exit 1
  fi
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
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a
  addr="${OATD_ADDR:-127.0.0.1:8080}"
  url="http://${addr}/readyz"
  log "Checking ${instance} at ${url}"
  curl -fsS "$url" >/dev/null
done

log "All instances ready"
