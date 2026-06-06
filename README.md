# Open Agentic Threat Defense

Open Agentic Threat Defense is a defensive control plane for detecting and
containing agentic threat behavior across AI-agent tool calls, host telemetry,
network egress, deception signals, and response workflows.

The current MVP is intentionally safe: it does not include exploit logic,
malware behavior, or autonomous propagation. Demo data generates telemetry only.

## What Exists Now

- Go HTTP service with Postgres persistence for production and JSON snapshot
  fallback for local development.
- Policy engine for agent-tool abuse, secret exposure, unexpected egress,
  discovery behavior, deception hits, and suspicious model runtime activity.
- Correlator for multi-signal sequences such as discovery, credential touch,
  agent tool call, and outbound flow.
- Dry-run response planner for host isolation, egress blocking, tool disabling,
  ticket creation, and secret rotation.
- User/token authentication with role-based access control.
- Audit log for authentication failures, RBAC denials, ingestion, response
  planning, and response approvals.
- `oadtdctl replay` for safe JSONL telemetry replay into the ingest API.
- Browser dashboard with asset risk graph, alerts, events, rules, and response
  actions.
- Alert webhook export for SIEM-style integrations.
- systemd and Windows service starter packaging.
- AGPLv3-or-later community license, commercial dual-license path, and CLA from
  day 1.

## Quick Start

Run the service with safe demo telemetry:

```powershell
$env:APPDATA="$PWD\.cache\appdata"
$env:GOTELEMETRY="off"
$env:GOCACHE="$PWD\.cache\go-build"
$env:GOMODCACHE="$PWD\.cache\go-mod"
go run ./cmd/oadtd --demo
```

Run with Postgres persistence:

```powershell
docker compose up -d postgres
$env:OATD_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
go run ./cmd/oadtd --demo --policy configs\example.policy.json
```

Run with local JSON persistence for development:

```powershell
go run ./cmd/oadtd --demo --data .cache\oadtd-state.json
```

Run with an explicit policy configuration:

```powershell
go run ./cmd/oadtd --demo --policy configs\example.policy.json
```

Open:

```text
http://localhost:8080
```

Run tests:

```powershell
$env:APPDATA="$PWD\.cache\appdata"
$env:GOTELEMETRY="off"
$env:GOCACHE="$PWD\.cache\go-build"
$env:GOMODCACHE="$PWD\.cache\go-mod"
go test ./...
```

Run the optional Postgres integration test:

```powershell
docker compose up -d postgres
$env:OATD_TEST_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
go test ./internal/store -run TestPostgresPersistenceIntegration -count=1
```

Replay safe JSONL telemetry into a running server:

```powershell
go run ./cmd/oadtdctl replay --file examples\demo-events.jsonl
```

## API

Ingest one event:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/events -ContentType application/json -Body '{
  "kind": "agent_tool_call",
  "asset_id": "dev-agent-01",
  "hostname": "dev-agent-01",
  "actor": "local-agent",
  "tool_name": "shell_exec",
  "command": "read env token",
  "signal": "agent referenced token material",
  "labels": ["agent", "credential"]
}'
```

With write-token protection enabled:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/events `
  -Headers @{ Authorization = "Bearer $env:OATD_API_TOKEN" } `
  -ContentType application/json `
  -Body '{"kind":"deception_hit","asset_id":"dev-agent-01","signal":"canary token touched"}'
```

Useful endpoints:

- `GET /api/status`
- `GET /api/events`
- `POST /api/events`
- `GET /api/alerts`
- `GET /api/assets`
- `GET /api/audit`
- `GET /api/policies`
- `GET /api/responses`
- `POST /api/responses`
- `POST /api/demo`

## Runtime Options

```text
--addr                 HTTP listen address, default :8080
--web                  static dashboard directory, default web
--demo                 load safe demo telemetry at startup
--data                 optional JSON snapshot path for local development persistence
--postgres-dsn         Postgres DSN for production persistence, defaults to OATD_POSTGRES_DSN
--policy               optional JSON policy configuration path
--api-token            legacy admin token, defaults to OATD_API_TOKEN
--alert-webhook-url    optional SIEM/webhook URL for new alerts
--alert-webhook-token  optional bearer token for alert webhook
```

When users are configured in the policy file, all API endpoints require
`Authorization: Bearer <token>` or `X-OATD-Token: <token>` and are checked
against RBAC roles. `--api-token` remains a legacy admin-token compatibility
path.

## Policy Configuration

The policy file is JSON:

```json
{
  "approved_tools": ["asset_inventory", "ticket_create", "policy_read", "siem_search"],
  "approved_egress_hosts": ["api.openai.com", "github.com", "login.microsoftonline.com"],
  "correlation_window": "30m",
  "users": [
    {
      "name": "admin",
      "token_sha256": "replace-with-sha256-token-hash",
      "roles": ["admin"]
    }
  ]
}
```

See [configs/example.policy.json](configs/example.policy.json) and
[configs/example.rbac.policy.json](configs/example.rbac.policy.json).

Create a token hash:

```powershell
go run ./cmd/oadtdctl token-hash --token "replace-with-secret-token"
```

Roles:

- `viewer`: read-only API access.
- `ingestor`: read API access and event/demo ingestion.
- `analyst`: read API access, ingestion, and response planning.
- `operator`: analyst permissions plus response approvals.
- `admin`: all API operations.

Audit logs require `analyst`, `operator`, or `admin`.

## Telemetry Replay

`oadtdctl replay` reads newline-delimited JSON events and posts them to
`/api/events`.

```powershell
go run ./cmd/oadtdctl replay --file examples\demo-events.jsonl --url http://localhost:8080
```

With write-token protection:

```powershell
go run ./cmd/oadtdctl replay --file examples\demo-events.jsonl --token $env:OATD_API_TOKEN
```

Validate a file without sending it:

```powershell
go run ./cmd/oadtdctl replay --file examples\demo-events.jsonl --dry-run
```

Normalize external defensive logs to OATD JSONL:

```powershell
go run ./cmd/oadtdctl collect --source suricata-eve --file eve.json --output events.jsonl
go run ./cmd/oadtdctl collect --source zeek-conn --file conn.log --output events.jsonl
go run ./cmd/oadtdctl collect --source sysmon-json --file sysmon.jsonl --output events.jsonl
go run ./cmd/oadtdctl collect --source auditd --file audit.log --output events.jsonl
```

Operations notes are in [docs/operations.md](docs/operations.md).

## License

Community distribution is licensed under AGPL-3.0-or-later.

Commercial licenses are available separately for organizations that need
closed-source redistribution, proprietary network use, enterprise terms, or
support. See [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

External contributions require a signed CLA before merge. See [CLA.md](CLA.md).

## Safety Boundary

This project is for authorized defensive monitoring and response simulation.
Do not add exploit code, malware behavior, credential theft tooling, or
autonomous propagation logic.
