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
  secret exposure, unexpected egress, discovery, lateral movement, destructive
  impact, deception hits, suspicious model runtime activity, and versioned
  threat-pack content.
- Tool-provenance verification: when a signed tool fingerprint is declared for a
  tool, the gateway denies a provenance mismatch (spoofed/tampered tool) and
  gates a missing fingerprint - supply-chain control for agent tools.
- Agent-identity verification: registered agents present a signed identity token;
  the gateway denies impersonation (token mismatch) and gates unknown or
  unidentified agents, so tool calls are attributed to a verified agent rather
  than a spoofable actor string.
- Inline tool-call PEP for enforce-before-execute decisions at the tool
  boundary, backed by a separate PDP endpoint for diagnostics.
- Gateway queue, approval polling, a transport proxy for tool backends, and an
  MCP reverse-proxy that classifies each method by surface - passing through
  lifecycle/enumeration/notifications, gating `tools/call` against the approved
  list, and content-gating resource/prompt/sampling/completion surfaces.
- Org-scoped policy sets: per-tenant overrides of the approved-tool and
  approved-egress allowlists applied inline in the gateway, managed by an
  admin-only API or seeded from a file at startup.
- Deception/canary token registry with a management API, plus hot policy and
  threat-pack reload via `SIGHUP` or an admin endpoint.
- Correlator for multi-signal sequences such as discovery, credential touch,
  agent tool call, and outbound flow.
- Dry-run response planner for host isolation, egress blocking, tool disabling,
  ticket creation, and secret rotation, with approval-gated execution export.
- Native incident-ticket connectors for GitHub issues, Jira, and ServiceNow,
  plus a generic ticket webhook, dispatched first-enabled-wins.
- GitHub workflow dispatch for approval-gated response execution.
- User/token authentication with role-based access control, plus OIDC and SAML
  single sign-on and logical or physical multi-tenancy.
- Ed25519-signed commercial license tokens with an edition-status endpoint and
  an `oadtdctl license` keygen/issue/verify workflow.
- Audit log for authentication failures, RBAC denials, ingestion, response
  planning, and response approvals, with tamper-evident hash chaining and a
  validation endpoint.
- Per-asset investigation timeline endpoint.
- `oadtdctl replay` for safe JSONL telemetry replay into the ingest API.
- `oadtdctl validate` for authorized, benign detection validation - a library of
  MITRE ATT&CK-mapped tool-call emulations scored against the inline gateway.
- `oadtdctl mcp-demo` (with `oadtdctl mcp-stub`) for an end-to-end proof that the
  MCP reverse-proxy gates a real MCP client's tool calls live, and `oadtdctl
  bench` for inline-gateway latency/throughput numbers.
- A LangChain reference integration in [examples/langchain](examples/langchain)
  that gates a third-party agent framework's tool calls through the gateway.
- `oadtdctl agent` for long-running tail-based collection from supported
  defensive telemetry sources, including native Windows Event Log and Linux
  journald modes.
- Browser dashboard with asset risk graph, alerts, events, rules, response
  actions, and a live ATT&CK detection-coverage panel, plus session-based
  dashboard login.
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
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

The server binds to a loopback address by default. Binding a non-loopback
address requires authentication, or `--insecure` for an explicitly open mode.

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

GitHub CI runs the same test suite with a real Postgres service, smoke-tests a
live startup, and builds Linux/Windows binaries for `amd64` and `arm64`.

GitHub security automation includes CodeQL analysis and Dependabot updates for
Go modules and GitHub Actions, plus dependency-review checks on pull requests.

Tagged releases publish platform binaries, an SPDX SBOM, and a `SHA256SUMS`
manifest (covering the binaries and the SBOM). The release workflow signs the
checksum manifest with Sigstore keyless signing. Verify a downloaded release
against the published bundle before trusting it:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity "https://github.com/hunterinvariants/open-agentic-threat-defense/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
sha256sum -c SHA256SUMS   # then check the binary against the verified manifest
```

Postgres operators can create and restore portable JSON backups with
`oadtdctl backup` and `oadtdctl restore`.

Run the optional Postgres integration test:

```powershell
docker compose up -d postgres
$env:OATD_TEST_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
go test ./internal/store -run TestPostgresPersistenceIntegration -count=1
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

Endpoints (RBAC roles apply only when authentication is configured):

| Method | Path | Roles | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` | none | Liveness probe returning version |
| GET | `/readyz` | none | Readiness probe pinging storage |
| GET | `/api/status` | any authenticated | Tenant-scoped counts and gateway/storage status |
| GET/POST/DELETE | `/api/session` | none | Session/SSO info, login, logout |
| GET | `/api/sso/oidc/login`, `/api/sso/oidc/callback` | none | OIDC SSO login and callback |
| GET | `/api/sso/saml/login`, `/api/sso/saml/complete` | none | SAML SSO login and completion |
| POST | `/api/gateway/decide` | ingestor, analyst, operator | Gate a tool call and return a verdict (PDP) |
| POST | `/api/gateway/execute` | ingestor, analyst, operator | Gate then allow/block/queue/execute a tool call (PEP) |
| POST | `/api/gateway/proxy` | ingestor, analyst, operator | Gate and forward a tool call to an upstream URL |
| POST | `/api/mcp/proxy` | ingestor, analyst, operator | Gate and forward a request to the MCP upstream |
| GET | `/api/gateway/queue` | analyst, operator | List pending gateway approval actions |
| GET | `/api/gateway/actions/{id}` | analyst, operator | Fetch a single gateway action |
| POST | `/api/policy/reload` | admin | Hot-reload policy and threat-pack files |
| GET/POST/PUT/DELETE | `/api/policy/tenants` | admin | Manage per-tenant policy overlays |
| GET/POST/DELETE | `/api/deception/tokens` | operator | List, register, and remove deception tokens |
| GET | `/api/timeline` | any authenticated | Chronological investigation view for one asset |
| GET | `/api/license` | any authenticated | Report license/edition status |
| GET/POST | `/api/events` | GET: any authenticated; POST: ingestor, analyst, operator | List or ingest events |
| GET | `/api/alerts` | any authenticated | List tenant alerts |
| GET | `/api/assets` | any authenticated | List tenant assets |
| GET | `/api/policies` | any authenticated | List active policy rules |
| GET | `/api/audit` | analyst, operator | List tenant audit log entries |
| GET | `/api/audit/chain` | analyst, operator | Return the hash-chained audit log |
| GET/POST | `/api/responses` | GET: any authenticated; POST: analyst, operator | List response actions or plan actions for an alert |
| POST | `/api/responses/approve` | operator | Approve and execute a pending response action |
| GET/POST | `/api/tenants` | admin | List or register tenant backends |
| GET/PUT/DELETE | `/api/tenants/{id}` | admin | Get, update, or delete one tenant backend |
| POST | `/api/demo` | ingestor, analyst, operator | Load demo events for the tenant |

## Runtime Options

```text
Core
--addr                  HTTP listen address (default :8080)
--web                   static dashboard directory (default web)
--demo                  load safe demo telemetry at startup
--insecure              allow open mode on non-loopback listen addresses
--retention-window      retention window for events, alerts, actions, audits (default 30d)
--gateway-max-in-flight max in-flight gateway operations before backpressure (default 64)
--trusted-proxies       comma-separated trusted proxy CIDRs or IPs

Persistence and policy
--data                  optional JSON snapshot path for local persistence
--postgres-dsn          Postgres DSN, defaults to OATD_POSTGRES_DSN
--policy                optional JSON policy configuration path
--threat-pack           optional threat pack JSON file
--deception-tokens      optional JSON file of deception/canary tokens
--tenant-policies       optional JSON file of org-scoped policy sets

Authentication and licensing
--api-token             legacy admin token, defaults to OATD_API_TOKEN
--license-file          path to a commercial license token file
--license-public-key    base64 ed25519 public key to verify the license

Webhooks
--alert-webhook-url / --alert-webhook-token         new-alert SIEM/webhook export
--ticket-webhook-url / --ticket-webhook-token       incident ticket webhook
--response-webhook-url / --response-webhook-token    approved response webhook

GitHub integration
--github-api-base       optional GitHub API base URL
--github-owner          GitHub owner for issue and workflow integrations
--github-repo           GitHub repository for issue and workflow integrations
--github-token          GitHub token for issue and workflow integrations
--github-workflow-file  GitHub workflow file for approved response actions
--github-workflow-ref   GitHub ref for workflow dispatch

Jira integration
--jira-base-url         Jira base URL for incident tickets
--jira-email            Jira account email
--jira-api-token        Jira API token
--jira-project-key      Jira project key for incidents
--jira-issue-type       Jira issue type (default Task)

ServiceNow integration
--servicenow-url        ServiceNow instance URL for incidents
--servicenow-user       ServiceNow user
--servicenow-password   ServiceNow password

MCP interception
--mcp-upstream-url      upstream MCP server URL for transparent interception
--mcp-upstream-token    optional bearer token for the MCP upstream

OIDC single sign-on
--oidc-issuer-url       OIDC issuer URL for SSO login
--oidc-client-id        OIDC client ID
--oidc-client-secret    OIDC client secret
--oidc-redirect-url     OIDC redirect URL
--oidc-scopes           comma-separated OIDC scopes (default openid,profile,email)
--oidc-tenant-claim     OIDC claim name for tenant assignment
--oidc-role-claim       OIDC claim name for roles
--oidc-email-claim      OIDC claim name for username/email

SAML single sign-on
--saml-root-url         SAML service provider root URL
--saml-idp-metadata-url SAML identity provider metadata URL
--saml-key-path         SAML signing key path
--saml-cert-path        SAML signing certificate path
--saml-tenant-attribute SAML attribute name for tenant assignment
--saml-role-attribute   SAML attribute name for roles
--saml-email-attribute  SAML attribute name for username/email

High availability and multi-tenancy
--public-url            canonical public URL for HA and SSO callbacks
--instance-name         instance label for HA deployments
--tenant-isolation-mode logical or physical tenant isolation (default logical)
--tenant-registry-path  path to the tenant registry JSON
--tenant-postgres-dsn-template Postgres DSN template for physical tenant stores
--tenant-data-path-template    file path template for physical tenant stores
```

Every flag has a matching `OATD_*` environment variable (for example `--addr`
has no env var, while `--postgres-dsn` reads `OATD_POSTGRES_DSN`). A few
behaviors are env-only: `OATD_SESSION_SECRET` (required when authentication or
SSO is configured), `OATD_AUDIT_HMAC_SECRET` (anchors the audit hash chain),
and `OATD_MANIFEST_HMAC_SECRET` / `OATD_MANIFEST_REQUIRE_SIGNED` (threat-pack
manifest signing).

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

## Incident-Ticket Connectors

Confirmed or approved response actions can open an incident ticket. Connectors
are evaluated first-enabled-wins in this order: GitHub issue, Jira, ServiceNow,
then the generic ticket webhook. A connector is enabled only when all of its
required settings are present, and exactly one ticket is created per action.

GitHub issues use the GitHub integration flags above. Jira creates an issue via
`POST <jira-base-url>/rest/api/2/issue` with HTTP Basic auth (`email:api-token`):

```text
--jira-base-url     https://your-org.atlassian.net
--jira-email        bot@your-org.com
--jira-api-token    <api token>
--jira-project-key  SEC
--jira-issue-type   Task            # optional, defaults to Task
```

ServiceNow creates an incident via `POST <servicenow-url>/api/now/table/incident`
with HTTP Basic auth (`user:password`):

```text
--servicenow-url       https://your-instance.service-now.com
--servicenow-user      integration.user
--servicenow-password  <password>
```

The generic ticket webhook (`--ticket-webhook-url` / `--ticket-webhook-token`)
remains available as a fallback transport.

## Commercial License Tokens

The product ships as a community edition by default. A signed license token
upgrades the reported edition. Licenses are Ed25519-signed: the vendor issues
tokens with a private key, and a deployment verifies them with the public key,
so a license cannot be forged without the private key. This is the technical
edition gate; it is separate from the AGPL / commercial legal licensing below.

Generate a key pair (vendor side, keep the private key secret):

```powershell
go run ./cmd/oadtdctl license keygen
```

Issue a license for an organization:

```powershell
go run ./cmd/oadtdctl license issue `
  --private-key $env:OATD_LICENSE_PRIVATE_KEY `
  --org "Example Corp" --features sso,multi-tenant --valid-for 8760h
```

Verify a token against the public key:

```powershell
go run ./cmd/oadtdctl license verify --public-key <base64-public-key> --token <token>
```

Run the server with a license; `GET /api/license` reports the edition, features,
expiry, and validity:

```powershell
go run ./cmd/oadtd --addr 127.0.0.1:8080 `
  --license-file license.token --license-public-key <base64-public-key>
```

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

The policy and threat pack can be hot-reloaded without a restart by sending
`SIGHUP` or calling `POST /api/policy/reload` as an admin. Deception/canary
tokens can be seeded with `--deception-tokens` and managed at runtime through
`GET/POST/DELETE /api/deception/tokens`.

The inline gateway and proxy path enforce a bounded in-flight limit to apply
backpressure on the critical decision path; configure it with
`--gateway-max-in-flight` or `OATD_GATEWAY_MAX_IN_FLIGHT`.

The MCP reverse-proxy path is enabled by setting `--mcp-upstream-url` and an
optional `--mcp-upstream-token`.

### Org-Scoped Policy Sets

Each tenant can override the global approved-tool and approved-egress
allowlists. A non-empty list fully replaces the global list for that tenant's
gateway and detection decisions; an omitted list falls back to the global
policy, so a tenant without an overlay behaves exactly as before.

Overlays are managed through the admin-only `/api/policy/tenants` endpoint
(`GET` to list, `POST`/`PUT` to set, `DELETE?tenant_id=...` to remove) and can
be seeded at startup from a JSON file with `--tenant-policies`:

```json
[
  {
    "tenant_id": "acme",
    "approved_tools": ["asset_inventory", "siem_search"],
    "approved_egress": ["acme-cdn.example.net"]
  }
]
```

## Telemetry Replay and Collectors

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

Validate that the inline gateway enforces against realistic agent threat
patterns on your own authorized deployment. `oadtdctl validate` runs a curated
library of benign, MITRE ATT&CK-mapped tool-call emulations through the
read-only `/api/gateway/decide` path and prints a pass/fail scorecard (including
a benign baseline to catch false positives). It emits only synthetic descriptive
telemetry — no real commands or exploit payloads are executed:

```powershell
go run ./cmd/oadtdctl validate --url http://localhost:8080 --token $env:OATD_API_TOKEN
```

Use it after upgrades or policy changes as a detection regression check; a
non-zero exit means an expected verdict did not hold. Add `--json` for CI,
`--coverage` for an ATT&CK tactic/technique coverage map, or `--continuous
--interval 1h --webhook <url>` to run it as a long-lived monitor that alerts on
regression. Schedule it with the packaged `oadtd-validate.timer` (with an
`OnFailure=` webhook alert), and surface the latest result plus a trend
sparkline as a **Detection Coverage** panel in the dashboard via `--output` /
`--history` and `OATD_VALIDATION_RESULT_PATH` / `OATD_VALIDATION_HISTORY_PATH`
(see [docs/operations.md](docs/operations.md)).

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

Sign a threat-pack manifest (requires `OATD_MANIFEST_HMAC_SECRET`):

```powershell
go run ./cmd/oadtdctl sign-manifest --file configs\example.threat-pack.json
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
