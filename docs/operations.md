# Operations

## Linux systemd

Example unit:

```text
packaging/systemd/oadtd.service
```

Suggested layout:

```text
/opt/oadtd/oadtd
/opt/oadtd/oadtdctl
/etc/oadtd/policy.json
/etc/oadtd/oadtd.env
/var/lib/oadtd/state.json
```

For production, set Postgres in `/etc/oadtd/oadtd.env`:

```text
OATD_POSTGRES_DSN=postgres://oadtd:oadtd@postgres:5432/oadtd?sslmode=disable
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
sudo systemctl daemon-reload
sudo systemctl enable --now oadtd
```

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
go run ./cmd/oadtd --demo
```

The payload type is `oadtd.alerts`.

Incident ticket creation can be exported to a ticketing webhook transport:

```powershell
$env:OATD_TICKET_WEBHOOK_URL="https://ticketing.example.invalid/oatd"
$env:OATD_TICKET_WEBHOOK_TOKEN="replace-with-token"
go run ./cmd/oadtd --demo
```

The payload type is `oadtd.incident_ticket`.

Approved response actions can also be exported to a response webhook transport:

```powershell
$env:OATD_RESPONSE_WEBHOOK_URL="https://soar.example.invalid/oatd"
$env:OATD_RESPONSE_WEBHOOK_TOKEN="replace-with-token"
go run ./cmd/oadtd --demo
```

The payload type is `oadtd.response_action`.

GitHub can be used as a concrete execution target for incidents and approved
runbooks:

```powershell
$env:OATD_GITHUB_OWNER="hunterinvariants"
$env:OATD_GITHUB_REPO="open-agentic-threat-defense"
$env:OATD_GITHUB_TOKEN="replace-with-token"
$env:OATD_GITHUB_WORKFLOW_FILE="runbook.yml"
go run ./cmd/oadtd --demo
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

`GET /api/audit` requires `analyst`, `operator`, or `admin`.

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
browser.

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
