#!/usr/bin/env bash
# Sends one alert to the configured webhook when detection validation fails.
# Invoked via OnFailure= from oadtd-validate.service. When the result file written
# by `oadtdctl validate --output` shows a regression, the alert includes the
# failed techniques; otherwise it reports that the run did not complete.
#
# Configure in /etc/oadtd/validate.env:
#   OATD_VALIDATE_ALERT_URL=https://hooks.example/detection-regression
#   OATD_VALIDATE_ALERT_TOKEN=optional-bearer-token
#   OATD_VALIDATE_RESULT_FILE=/var/lib/oadtd/validation-last.json   # optional override
set -euo pipefail

RESULT_FILE="${OATD_VALIDATE_RESULT_FILE:-/var/lib/oadtd/validation-last.json}"
URL="${OATD_VALIDATE_ALERT_URL:-}"
TOKEN="${OATD_VALIDATE_ALERT_TOKEN:-}"
HOST="$(hostname -f 2>/dev/null || hostname)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -z "$URL" ]; then
  echo "oadtd-validate-alert: OATD_VALIDATE_ALERT_URL not set; nothing to send" >&2
  exit 0
fi

if [ -f "$RESULT_FILE" ] && jq -e '.passed != .total' "$RESULT_FILE" >/dev/null 2>&1; then
  payload="$(jq -c --arg host "$HOST" --arg ts "$TS" '{
    type: "detection_regression",
    host: $host, time: $ts,
    summary: "detection validation: \(.passed)/\(.total) held on \($host)",
    total: .total, passed: .passed, missed: .missed, false_positives: .false_positives,
    failed: [.results[] | select(.pass == false) | {technique, tactic, name, want, got}]
  }' "$RESULT_FILE")"
else
  payload="$(jq -nc --arg host "$HOST" --arg ts "$TS" '{
    type: "detection_validation_failed",
    host: $host, time: $ts,
    summary: "detection validation did not complete on \($host); see journalctl -u oadtd-validate.service"
  }')"
fi

args=(-fsS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json')
if [ -n "$TOKEN" ]; then
  args+=(-H "Authorization: Bearer ${TOKEN}")
fi
args+=(--data "$payload" "$URL")

code="$(curl "${args[@]}" 2>/dev/null || true)"
echo "oadtd-validate-alert: POST ${URL} -> HTTP ${code:-error}"
