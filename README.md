# Open Agentic Threat Defense

[![ci](https://github.com/hunterinvariants/open-agentic-threat-defense/actions/workflows/ci.yml/badge.svg)](https://github.com/hunterinvariants/open-agentic-threat-defense/actions/workflows/ci.yml)

Open Agentic Threat Defense is a defensive control plane for detecting and
containing agentic threat behavior across AI-agent tool calls, host telemetry,
network egress, deception signals, and response workflows.

The current MVP is intentionally safe: it does not include exploit logic,
malware behavior, or autonomous propagation. Demo data generates telemetry only.

## What Exists Now

- Go HTTP service with Postgres persistence for production and JSON snapshot
  fallback for local development.
- Policy engine for agent-tool abuse, taint-aware source-to-sink flow,
  secret exposure, unexpected egress, discovery behavior, deception hits,
  suspicious model runtime activity, and versioned threat-pack content.
- Inline tool-call PEP for enforce-before-execute decisions at the tool
  boundary, backed by a separate PDP endpoint for diagnostics.
- Gateway queue, approval polling, and a transport proxy for tool backends.
- Correlator for multi-signal sequences such as discovery, credential touch,
  agent tool call, and outbound flow.
- Dry-run response planner for host isolation, egress blocking, tool disabling,
  ticket creation, and secret rotation, with approval-gated execution export
  plus a separate incident-ticket connector.
- User/token authentication with role-based access control.
- Audit log for authentication failures, RBAC denials, ingestion, response
  planning, and response approvals.
- `oadtdctl replay` for safe JSONL telemetry replay into the ingest API.
- `oadtdctl agent` for long-running tail-based collection from supported
  defensive telemetry sources, including native Windows Event Log and Linux
  journald modes.
- Browser dashboard with asset risk graph, alerts, events, rules, and response
  actions, plus session-based dashboard login.
- Alert webhook export for SIEM-style integrations.
- Tamper-evident audit chaining and an audit chain endpoint for validation.
- GitHub issue creation for incident tickets and GitHub workflow dispatch for
  approval-gated response execution.
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
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

Run with Postgres persistence:

```powershell
docker compose up -d postgres
$env:OATD_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
$env:OATD_SESSION_SECRET="replace-with-a-strong-random-secret"
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080 --policy configs\example.policy.json
```

Run with local JSON persistence for development:

```powershell
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080 --data .cache\oadtd-state.json
```

Run with an explicit policy configuration:

```powershell
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080 --policy configs\example.policy.json
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

GitHub CI runs the same test suite with a real Postgres service and builds
Linux/Windows binaries for `amd64` and `arm64`.

GitHub security automation includes CodeQL analysis and Dependabot updates for
Go modules and GitHub Actions, plus dependency-review checks on pull requests.

Tagged releases publish platform binaries, an SPDX SBOM, and a `SHA256SUMS`
manifest. The release workflow also signs the checksum manifest with Sigstore
keyless signing.

Postgres operators can create and restore portable JSON backups with
`oadtdctl backup` and `oadtdctl restore`.

Approved response actions can be exported to an external webhook transport
after operator approval by setting:

```text
--ticket-webhook-url     optional webhook URL for incident ticket creation
--ticket-webhook-token   optional bearer token for ticket webhook
--response-webhook-url    optional webhook URL for approved response actions
--response-webhook-token  optional bearer token for response webhook
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

Gate a tool call before execution:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/gateway/execute -ContentType application/json -Body '{
  "asset_id": "dev-agent-01",
  "hostname": "dev-agent-01",
  "actor": "local-agent",
  "tool_name": "asset_inventory",
  "command": "inventory scan",
  "arguments": "token=abc123",
  "labels": ["agent", "tool-call"]
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

- `GET /healthz`
- `GET /readyz`
- `GET /api/status`
- `POST /api/gateway/decide`
- `POST /api/gateway/execute`
- `POST /api/gateway/proxy`
- `GET /api/gateway/queue`
- `GET /api/gateway/actions/{id}`
- `GET /api/events`
- `POST /api/events`
- `GET /api/alerts`
- `GET /api/assets`
- `GET /api/audit`
- `GET /api/audit/chain`
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
--ticket-webhook-url   optional webhook URL for incident ticket creation
--ticket-webhook-token optional bearer token for ticket webhook
--response-webhook-url optional webhook URL for approved response actions
--response-webhook-token optional bearer token for response webhook
--github-api-base      optional GitHub API base URL
--github-owner         GitHub owner for issue and workflow integrations
--github-repo          GitHub repository for issue and workflow integrations
--github-token         GitHub token for issue and workflow integrations
--github-workflow-file GitHub workflow file for approved response actions
--github-workflow-ref  GitHub ref for workflow dispatch
--oidc-issuer-url      OIDC issuer URL for SSO login
--oidc-client-id       OIDC client ID
--oidc-client-secret   OIDC client secret
--oidc-redirect-url    OIDC redirect URL
--oidc-scopes          comma-separated OIDC scopes, default openid,profile,email
--oidc-tenant-claim    OIDC claim name for tenant assignment
--oidc-role-claim      OIDC claim name for roles
--oidc-email-claim     OIDC claim name for username/email
--saml-root-url        SAML service provider root URL
--saml-idp-metadata-url SAML identity provider metadata URL
--saml-key-path        SAML signing key path
--saml-cert-path       SAML signing certificate path
--saml-tenant-attribute SAML attribute name for tenant assignment
--saml-role-attribute  SAML attribute name for roles
--saml-email-attribute SAML attribute name for username/email
--public-url           canonical public URL for HA and SSO callbacks
--instance-name        instance label for HA deployments
--tenant-isolation-mode logical or physical tenant isolation
--tenant-registry-path path to the tenant registry JSON
--tenant-postgres-dsn-template Postgres DSN template for tenant stores
--tenant-data-path-template file path template for tenant stores
```

When users are configured in the policy file, all API endpoints require
`Authorization: Bearer <token>` or `X-OATD-Token: <token>` and are checked
against RBAC roles. `--api-token` remains a legacy admin-token compatibility
path.

The dashboard uses `POST /api/session` to exchange a configured user name and
token for a session cookie, or `GET /api/sso/oidc/login` / `GET /api/sso/saml/login`
for SSO. `GET /api/session` reports the current dashboard state, includes SSO
availability, and `DELETE /api/session` logs out.

For HA, run multiple replicas behind a load balancer with the same Postgres
database, shared SAML signing material, and distinct `--instance-name` values.
`--public-url` should match the canonical external URL used by SSO callbacks
and health checks.

For physical tenant isolation, set `--tenant-isolation-mode physical` and
either `--tenant-postgres-dsn-template` or `--tenant-data-path-template`. The
dashboard exposes a tenant admin panel backed by `GET /api/tenants` and
`POST /api/tenants`.

## Policy Configuration

The policy file is JSON:

```json
{
  "approved_tools": ["asset_inventory", "ticket_create", "policy_read", "siem_search"],
  "approved_egress_hosts": ["api.openai.com", "github.com", "login.microsoftonline.com"],
  "threat_pack_path": "configs\\example.threat-pack.json",
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
The inline gateway and proxy path enforce a bounded in-flight limit to apply
backpressure on the critical decision path; configure it with
`--gateway-max-in-flight` or `OATD_GATEWAY_MAX_IN_FLIGHT`.

The MCP reverse-proxy path is enabled by setting:

```text
--mcp-upstream-url    upstream MCP server URL
--mcp-upstream-token  optional bearer token for the upstream
```

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

Run the wedge demo against a live server:

```powershell
go run ./cmd/oadtdctl wedge-demo --url http://localhost:8080 --approved-by operator --await-approval
```

Normalize external defensive logs to OATD JSONL:

```powershell
go run ./cmd/oadtdctl collect --source suricata-eve --file eve.json --output events.jsonl
go run ./cmd/oadtdctl collect --source zeek-conn --file conn.log --output events.jsonl
go run ./cmd/oadtdctl collect --source sysmon-json --file sysmon.jsonl --output events.jsonl
go run ./cmd/oadtdctl collect --source auditd --file audit.log --output events.jsonl
```

Run a long-lived collector agent that tails a source file and posts batches to
the ingest API:

```powershell
go run ./cmd/oadtdctl agent --source sysmon-json --file sysmon.jsonl --url http://localhost:8080 --state-file .cache\agent-state.json
```

Native collector modes:

```powershell
go run ./cmd/oadtdctl agent --source windows-eventlog --log-name Microsoft-Windows-Sysmon/Operational --url http://localhost:8080
go run ./cmd/oadtdctl agent --source journald --journal-unit ssh.service --url http://localhost:8080
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
