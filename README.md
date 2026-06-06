# Open Agentic Threat Defense

Open Agentic Threat Defense is a defensive control plane for detecting and
containing agentic threat behavior across AI-agent tool calls, host telemetry,
network egress, deception signals, and response workflows.

The current MVP is intentionally safe: it does not include exploit logic,
malware behavior, or autonomous propagation. Demo data generates telemetry only.

## What Exists Now

- Go HTTP service with in-memory storage or optional local JSON snapshot
  persistence.
- Policy engine for agent-tool abuse, secret exposure, unexpected egress,
  discovery behavior, deception hits, and suspicious model runtime activity.
- Correlator for multi-signal sequences such as discovery, credential touch,
  agent tool call, and outbound flow.
- Dry-run response planner for host isolation, egress blocking, tool disabling,
  ticket creation, and secret rotation.
- Optional token protection for write endpoints.
- Browser dashboard with asset risk graph, alerts, events, rules, and response
  actions.
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

Run with local persistence and write-token protection:

```powershell
$env:OATD_API_TOKEN="replace-with-a-local-secret"
go run ./cmd/oadtd --demo --data .cache\oadtd-state.json
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
- `GET /api/policies`
- `GET /api/responses`
- `POST /api/responses`
- `POST /api/demo`

## Runtime Options

```text
--addr       HTTP listen address, default :8080
--web        static dashboard directory, default web
--demo       load safe demo telemetry at startup
--data       optional JSON snapshot path for local persistence
--api-token  optional token for POST endpoints, defaults to OATD_API_TOKEN
```

When `--api-token` or `OATD_API_TOKEN` is set, read endpoints remain available
for the dashboard and health checks, while write endpoints require
`Authorization: Bearer <token>` or `X-OATD-Token: <token>`.

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
