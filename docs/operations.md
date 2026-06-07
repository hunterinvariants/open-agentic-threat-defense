# Operations

## Linux systemd

Example unit:

```text
packaging/systemd/oadtd.service
```

Suggested layout:

```text
/opt/oadtd/current/oadtd
/opt/oadtd/current/oadtdctl
/opt/oadtd/releases/<sha>/oadtd
/opt/oadtd/releases/<sha>/oadtdctl
/etc/oadtd/policy.json
/etc/oadtd/oadtd.env
/var/lib/oadtd/state.json
```

The service unit points at `/opt/oadtd/current`, so deployments can swap a
release symlink atomically and restart the service with a rollback available.

For production, set Postgres in `/etc/oadtd/oadtd.env`:

```text
OATD_POSTGRES_DSN=postgres://oadtd:oadtd@postgres:5432/oadtd?sslmode=disable
OATD_SESSION_SECRET=<strong-random-secret>
```

For local development and integration tests, start the bundled Compose service:

```powershell
docker compose up -d postgres
$env:OATD_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
```

Create a dedicated user, copy the binaries and policy file, install the unit,
then enable it:

```bash
sudo useradd --system --home /var/lib/oadtd --shell /usr/sbin/nologin oadtd
sudo mkdir -p /opt/oadtd /etc/oadtd /var/lib/oadtd
sudo chown -R oadtd:oadtd /var/lib/oadtd
sudo cp packaging/systemd/oadtd.service /etc/systemd/system/oadtd.service
sudo chown root:oadtd /etc/oadtd/policy.json
sudo chmod 0640 /etc/oadtd/policy.json
sudo systemctl daemon-reload
sudo systemctl enable --now oadtd
```

## GitHub Deploy

The repository includes a GitHub Actions deployment workflow for reachable
Ubuntu hosts. It expects a release layout like this:

```text
/opt/oadtd/releases/<sha>/oadtd
/opt/oadtd/releases/<sha>/oadtdctl
/opt/oadtd/current -> /opt/oadtd/releases/<sha>
```

The workflow needs SSH credentials and host details through repository or
environment secrets:

- `OATD_DEPLOY_HOST`
- `OATD_DEPLOY_PORT`
- `OATD_DEPLOY_USER`
- `OATD_DEPLOY_SSH_KEY`

The target user must be able to restart `oadtd` through `sudo` without an
interactive password prompt.

The actual release swap logic lives in `scripts/deploy-release.sh`. It prints
step groups, service status, and the last journal lines if a step fails, so the
GitHub Actions log shows the real failure point instead of only `exit 1`.

## GitHub Self-hosted Runner

For a local Ubuntu VM staging environment, the repository includes a
`deploy-self-hosted.yml` workflow that runs on a GitHub Actions self-hosted
runner installed on the VM itself. This avoids SSH hops and tests the exact
release swap used in production.

Expected runner labels:

- `self-hosted`
- `linux`
- `x64`
- `oadtd-staging`

Suggested one-time runner setup on the VM:

```bash
sudo useradd --system --create-home --home-dir /opt/actions-runner --shell /bin/bash runner
sudo mkdir -p /opt/actions-runner
sudo chown runner:runner /opt/actions-runner
```

Then run:

```bash
sudo bash scripts/setup-self-hosted-runner.sh
```

The script downloads the latest Linux x64 runner release, registers it against
the repository, and installs it as a service under the `runner` user. It uses
`gh auth token` or `GITHUB_TOKEN` to create the runner registration token.
That GitHub token must have repository admin access so GitHub can create the
runner registration token.

The runner user needs passwordless sudo for the deployment steps:

```bash
sudo visudo -f /etc/sudoers.d/oadtd-runner
```

Add:

```text
runner ALL=(root) NOPASSWD: /usr/bin/install, /bin/ln, /bin/rm, /bin/chown, /bin/systemctl, /usr/bin/journalctl
```

After the runner is online, trigger the workflow manually from GitHub and it
will:

- build the Linux binaries
- install them under `/opt/oadtd/releases/<sha>`
- repoint `/opt/oadtd/current`
- restart `oadtd`
- verify `GET /readyz`

## Windows Service

Build or download `oadtd.exe`, place it at `C:\Program Files\OATD\oadtd.exe`,
then run PowerShell as Administrator:

```powershell
.\packaging\windows\install-service.ps1
```

The script registers a Windows service named `OATD` and stores runtime state
under `C:\ProgramData\OATD`.

## Webhook Export

New alerts can be exported to a SIEM or webhook endpoint:

```powershell
$env:OATD_ALERT_WEBHOOK_URL="https://siem.example.invalid/oatd"
$env:OATD_ALERT_WEBHOOK_TOKEN="replace-with-token"
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

The payload type is `oadtd.alerts`.

Incident ticket creation can be exported to a ticketing webhook transport:

```powershell
$env:OATD_TICKET_WEBHOOK_URL="https://ticketing.example.invalid/oatd"
$env:OATD_TICKET_WEBHOOK_TOKEN="replace-with-token"
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

The payload type is `oadtd.incident_ticket`.

Approved response actions can also be exported to a response webhook transport:

```powershell
$env:OATD_RESPONSE_WEBHOOK_URL="https://soar.example.invalid/oatd"
$env:OATD_RESPONSE_WEBHOOK_TOKEN="replace-with-token"
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

The payload type is `oadtd.response_action`.

GitHub can be used as a concrete execution target for incidents and approved
runbooks:

```powershell
$env:OATD_GITHUB_OWNER="hunterinvariants"
$env:OATD_GITHUB_REPO="open-agentic-threat-defense"
$env:OATD_GITHUB_TOKEN="replace-with-token"
$env:OATD_GITHUB_WORKFLOW_FILE="runbook.yml"
go run ./cmd/oadtd --demo --addr 127.0.0.1:8080
```

Incident plans create GitHub issues. Approved response actions dispatch the
configured workflow file.

## Storage

Production durable storage is Postgres via `--postgres-dsn` or
`OATD_POSTGRES_DSN`. OATD creates and upgrades the required tables through
versioned migrations tracked in `oatd_schema_migrations`.

The local JSON snapshot configured with `--data` remains useful for development
and quick labs, but it is not the production storage path.

`GET /api/status` exposes the active `schema_version` when Postgres is enabled.

The optional Postgres integration test is disabled by default and runs only when
`OATD_TEST_POSTGRES_DSN` is set:

```powershell
$env:OATD_TEST_POSTGRES_DSN="postgres://oadtd:oadtd@localhost:5432/oadtd?sslmode=disable"
go test ./internal/store -run TestPostgresPersistenceIntegration -count=1
```

Portable backups are JSON snapshots produced by `oadtdctl backup` and restored
with `oadtdctl restore`:

```powershell
go run ./cmd/oadtdctl backup --postgres-dsn $env:OATD_POSTGRES_DSN --output backup.json
go run ./cmd/oadtdctl restore --postgres-dsn $env:OATD_POSTGRES_DSN --input backup.json
```

The service also exposes `GET /healthz` and `GET /readyz` for process and
database readiness checks.

Response actions are split by connector:

- `create_incident_ticket` uses the ticket webhook as soon as the plan is stored.
- approval-required actions use the response webhook only after operator approval.

## Collector Agents

Long-running collector agents tail source files, persist offsets, normalize new
content, and submit batches to the ingest API.

Example:

```powershell
go run ./cmd/oadtdctl agent --source sysmon-json --file sysmon.jsonl --url http://localhost:8080 --state-file .cache\agent-state.json
```

Use `--once` for a single pass over the current file contents, or omit it to
keep polling for appended telemetry.

Native source modes are also available:

```powershell
go run ./cmd/oadtdctl agent --source windows-eventlog --log-name Microsoft-Windows-Sysmon/Operational --url http://localhost:8080
go run ./cmd/oadtdctl agent --source journald --journal-unit ssh.service --url http://localhost:8080
```

## Audit Log

The service records audit events for authentication failures, RBAC denials,
event ingestion, demo loads, response planning, and response approvals. Audit
events are stored in Postgres table `oatd_audit_events` in production mode and
are exposed through `GET /api/audit`.
Audit records are hash-chained and the chain state is visible through
`GET /api/audit/chain`.

`GET /api/audit` requires `analyst`, `operator`, or `admin`.
`GET /api/audit/chain` requires `analyst`, `operator`, or `admin`.

## Gateway Control

The inline gateway enforces a bounded in-flight limit on the critical path.
Set `--gateway-max-in-flight` or `OATD_GATEWAY_MAX_IN_FLIGHT` to control
backpressure. `POST /api/gateway/proxy` forwards tool payloads to configured
upstreams only after the gate allows them.

The transparent MCP proxy uses `--mcp-upstream-url` and optional
`--mcp-upstream-token` to forward JSON-RPC MCP traffic through OADTD while the
gate inspects tool-like calls inline.

## RBAC

Define users in the policy file with token hashes:

```json
{
  "users": [
    {
      "name": "admin",
      "token_sha256": "replace-with-sha256-token-hash",
      "roles": ["admin"]
    }
  ]
}
```

Generate a hash:

```powershell
.\oadtdctl.exe token-hash --token "replace-with-secret-token"
```

## Dashboard Login

The dashboard uses a session cookie instead of storing bearer tokens in the
browser. It also supports OIDC SSO when `OATD_OIDC_ISSUER_URL`,
`OATD_OIDC_CLIENT_ID`, and `OATD_OIDC_REDIRECT_URL` are configured, plus SAML
SSO when `OATD_SAML_ROOT_URL`, `OATD_SAML_IDP_METADATA_URL`, and a signing
key/certificate are configured.

Login:

```http
POST /api/session
Content-Type: application/json

{"username":"admin","token":"replace-with-secret-token"}
```

Check the current session:

```http
GET /api/session
```

Logout:

```http
DELETE /api/session
```

## High Availability

OADTD is designed to run as multiple stateless replicas behind a load
balancer. Use the same Postgres database for all replicas, keep SSO signing
material shared, and set a distinct `--instance-name` on each node. Set
`--public-url` to the canonical external URL used by SSO callbacks and health
checks.

Example instance start:

```bash
sudo install -d -o root -g root /etc/oadtd
sudo install -o root -g root -m 0640 /path/to/blue.env /etc/oadtd/blue.env
sudo install -o root -g root -m 0640 /path/to/green.env /etc/oadtd/green.env
sudo systemctl daemon-reload
sudo systemctl enable --now oadtd@blue
sudo systemctl enable --now oadtd@green
```

Example failover check:

```bash
curl -fsS http://blue-host/readyz
curl -fsS http://green-host/readyz
```

Use the reverse proxy example in `packaging/nginx/oadtd.conf` to place a load
balancer in front of multiple instances.
