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

The packaged unit binds `127.0.0.1:8080` and runs as the non-root `oadtd` user
under a full systemd sandbox (`ProtectSystem=strict`, `SystemCallFilter`,
`RestrictAddressFamilies`, empty `CapabilityBoundingSet`, `MemoryDenyWriteExecute`,
`UMask=0077`, and more — `systemd-analyze security oadtd` ≈ 1.5/OK). Reach the
dashboard through a reverse proxy or an SSH tunnel
(`ssh -L 8080:127.0.0.1:8080 host`), and keep `/etc/oadtd/*.env` at mode `0600`.

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
the repository, and installs it as a service **running as the non-root `runner`
user** (not root). It uses `gh auth token` or `GITHUB_TOKEN` (a repository-admin
token) to create the runner registration token.

It also installs a fixed, root-owned deploy entrypoint at
`/usr/local/sbin/oadtd-deploy` plus a root-owned copy of `deploy-release.sh`
under `/opt/oadtd/bin/`, and grants the runner passwordless sudo for **only the
wrapper** — not arbitrary privileged commands:

```text
runner ALL=(root) NOPASSWD: /usr/local/sbin/oadtd-deploy
```

The wrapper validates its inputs and runs the root-owned deploy script, so the
runner can trigger a deploy of the built artifacts but cannot perform arbitrary
root actions; a build-time supply-chain compromise is confined to the
unprivileged runner account. Do not run the runner service as root.

After the runner is online, trigger the workflow manually from GitHub (the
deployable ref is allowlisted to `main` / `vX.Y.Z`) and it will:

- build the Linux binaries (as the non-root runner)
- call `sudo /usr/local/sbin/oadtd-deploy` to install them under
  `/opt/oadtd/releases/<sha>`, repoint `/opt/oadtd/current`, restart `oadtd`, and
  verify `GET /readyz`

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

Native Jira and ServiceNow connectors create incidents directly when configured:

```text
OATD_JIRA_BASE_URL=https://your-org.atlassian.net
OATD_JIRA_EMAIL=bot@your-org.com
OATD_JIRA_API_TOKEN=replace-with-token
OATD_JIRA_PROJECT_KEY=SEC
OATD_SERVICENOW_URL=https://your-instance.service-now.com
OATD_SERVICENOW_USER=integration.user
OATD_SERVICENOW_PASSWORD=replace-with-password
```

Ticket connectors are tried first-enabled-wins: GitHub issue, Jira, ServiceNow,
then the generic ticket webhook.

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

## Detection Validation

`oadtdctl validate` checks that the inline gateway still enforces against
realistic agent threat patterns on your own authorized deployment. It runs a
curated library of benign, MITRE ATT&CK-mapped tool-call emulations through the
read-only `/api/gateway/decide` endpoint and scores each against its expected
verdict, plus a benign baseline to catch false positives. Each emulation is
tagged with its own gateway history key, so results are deterministic and
order-independent across repeated runs.

```powershell
go run ./cmd/oadtdctl validate --url http://localhost:8080 --token $env:OATD_API_TOKEN
```

The emulations carry only synthetic descriptive strings — no real commands,
exploits, or attack payloads run against any target. Run it after upgrades or
policy changes; it exits non-zero if an expected verdict did not hold, so it can
gate a deploy. Add `--json` for machine-readable output in CI. Sample run:

```text
oadtdctl validate — agent-gateway detection validation
  PASS  -            benign-baseline         want=allow                  got=allow
  PASS  T1552.001    secret-in-context       want=>=require_approval     got=require_approval
  PASS  T1057        discovery-chain         want=>=require_approval     got=require_approval
  PASS  T1083        file-discovery          want=>=require_approval     got=require_approval
  PASS  T1059        prompt-injection        want=>=require_approval     got=require_approval
  PASS  T1027        obfuscated-secret       want=>=require_approval     got=require_approval
  PASS  T1140        deobfuscate-execute     want=>=require_approval     got=require_approval
  PASS  T1071.001    web-c2-beacon           want=>=require_approval     got=require_approval
  PASS  T1567        unapproved-egress       want=>=require_approval     got=require_approval
  PASS  T1530        canary-touch            want=>=deny                 got=deny
  PASS  TA0002       unapproved-tool         want=>=deny                 got=deny

Summary: 11/11 held  (0 missed, 0 false positives)
```

### ATT&CK coverage map

`--coverage` groups the same run by tactic/technique and marks each `HELD` or
`GAP`, for a coverage report you can attach to an audit:

```powershell
go run ./cmd/oadtdctl validate --url http://localhost:8080 --token $env:OATD_API_TOKEN --coverage
```

### Continuous monitoring and scheduling

For ongoing assurance, validate on a schedule. Two options:

- **systemd timer (recommended):** install the packaged
  `oadtd-validate.service` (oneshot) and `oadtd-validate.timer`. The service
  reads a least-privilege token via `--token-file /etc/oadtd/validation.token`
  (make it readable by the `oadtd` user: `chown oadtd:oadtd`, `chmod 600`) and
  writes the latest result with `--output /var/lib/oadtd/validation-last.json`.
  Enable with `systemctl enable --now oadtd-validate.timer`.
- **Long-lived monitor:** `oadtdctl validate --continuous --interval 1h
  --webhook https://hooks.example/regress` re-runs the suite on an interval and
  POSTs a JSON alert (`type: detection_regression`) to the webhook whenever a
  detection stops holding.

Create the least-privilege validation identity by adding an `ingestor` user to
`policy.json` (`oadtdctl token-hash` produces the `token_sha256`), then restart
the server so the new user loads. Store the raw token only in the root-readable
`--token-file`.

### Alerting on regression

`oadtd-validate.service` ships with `OnFailure=oadtd-validate-alert.service`. When
a run regresses (or fails to complete), the alert unit runs
`/usr/local/sbin/oadtd-validate-alert`, which reads the result file and POSTs a
single webhook alert — rich (with the failed techniques) when a result is
available, generic otherwise. Install the script and configure the destination:

```bash
# install the alert helper + units (raw files from the repo)
base=https://raw.githubusercontent.com/hunterinvariants/open-agentic-threat-defense/main
curl -fsSL "$base/scripts/oadtd-validate-alert.sh" -o /usr/local/sbin/oadtd-validate-alert
chmod 0755 /usr/local/sbin/oadtd-validate-alert
for u in oadtd-validate.service oadtd-validate.timer oadtd-validate-alert.service; do
  curl -fsSL "$base/packaging/systemd/$u" -o "/etc/systemd/system/$u"
done

# configure the webhook (root-only)
umask 077
cat >/etc/oadtd/validate.env <<'ENV'
OATD_VALIDATE_ALERT_URL=https://hooks.example/detection-regression
OATD_VALIDATE_ALERT_TOKEN=optional-bearer-token
ENV

systemctl daemon-reload && systemctl enable --now oadtd-validate.timer
```

### Coverage in the dashboard

Point the server at the same result file and the dashboard shows a live
**Detection Coverage** panel (`GET /api/gateway/validation`, read-only, viewer
role). Set `OATD_VALIDATION_RESULT_PATH` in `/etc/oadtd/oadtd.env` and restart:

```bash
echo 'OATD_VALIDATION_RESULT_PATH=/var/lib/oadtd/validation-last.json' >> /etc/oadtd/oadtd.env
systemctl restart oadtd
```

The panel reads the file the validation timer writes — no re-running of the
suite on page load, so it never touches the live gateway from the browser.

## Audit Log

The service records audit events for authentication failures, RBAC denials,
event ingestion, demo loads, policy and tenant changes, gateway decisions,
response planning, and response approvals. Audit events are stored in Postgres
table `oatd_audit_events` in production mode and are exposed through
`GET /api/audit`. Records are hash-chained, HMAC-anchored with a server-held key,
and (in the Postgres path) re-derived from the rows at read time so DB tampering
is detected at runtime; the chain state is visible through `GET /api/audit/chain`.

`GET /api/audit` requires `analyst`, `operator`, or `admin`.
`GET /api/audit/chain` requires `analyst`, `operator`, or `admin`.

## Gateway Control

The inline gateway enforces a bounded in-flight limit on the critical path.
Set `--gateway-max-in-flight` or `OATD_GATEWAY_MAX_IN_FLIGHT` to control
backpressure. `POST /api/gateway/proxy` forwards tool payloads to configured
upstreams only after the gate allows them.

The transparent MCP proxy uses `--mcp-upstream-url` and optional
`--mcp-upstream-token` to forward JSON-RPC MCP traffic through OADTD while the
gate inspects tool-like calls inline. The proxy reaches loopback/internal
upstreams only with the explicit `--proxy-allow-local-targets` flag (off by
default); both proxy endpoints are refused when authentication is not configured.

## Policy, License, and Deception

Hot-reload the active policy and threat pack without a restart (admin), or send
`SIGHUP` to the process:

```http
POST /api/policy/reload
```

Manage per-tenant org-scoped policy overlays (approved tools / egress); seed them
at startup with `--tenant-policies`:

```http
GET/POST/DELETE /api/policy/tenants    # admin
```

Seed deception/canary tokens with `--deception-tokens` and manage them at
runtime; a hit is denied inline by the gateway:

```http
GET/POST/DELETE /api/deception/tokens  # operator
```

Gate the commercial edition with an Ed25519 license token:

```bash
oadtdctl license keygen
oadtdctl license issue --private-key $OATD_LICENSE_PRIVATE_KEY --org "Example" \
  --features sso,multi-tenant --valid-for 8760h
# run with --license-file license.token --license-public-key <base64-public-key>
# status:  GET /api/license   (community edition when none is configured)
```

A per-asset investigation timeline is available at `GET /api/timeline`.

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
SSO when `OATD_SAML_ROOT_URL`, `OATD_SAML_IDP_METADATA_URL`, and explicit
signing key/certificate paths are configured.

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

Use the reverse proxy example in `packaging/nginx/oadtd.conf` to place a TLS
terminating load balancer in front of multiple instances.
