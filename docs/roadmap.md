# Roadmap

## Hours: MVP

- Safe demo telemetry.
- Policy engine.
- Correlation engine.
- Dry-run response planner.
- Local dashboard.
- Postgres persistence for production.
- Optional JSON snapshot persistence for local development.
- User-token authentication with RBAC roles.
- JSON policy configuration for tool, egress, and correlation-window defaults.
- Safe JSONL telemetry replay client.
- Collector normalizers for Sysmon JSON, auditd, Zeek conn, and Suricata EVE.
- Long-running collector agents for Sysmon, auditd, Zeek, and Suricata.
- Alert webhook export.
- Response approval state for planned actions and webhook-based execution export.
- GitHub issue creation for incident tickets and GitHub workflow dispatch for
  approved runbooks.
- Audit logging for authentication, RBAC, ingestion, planning, and approval
  events.
- Docker Compose Postgres service plus optional Postgres integration test.
- Versioned Postgres schema migrations.
- CodeQL, Dependabot, dependency review, and release SBOM/checksum/signing
  GitHub automation.
- systemd and Windows service starter packaging.
- AGPLv3-or-later plus commercial dual-license path.
- CLA requirement from day 1.

Status: implemented in this repository.

## 1-2 Weeks: Alpha

- Postgres backup/restore tooling and docs.
- Session-based dashboard login on top of token/RBAC API.
- Policy reload without restart.
- Signed tool manifests for AI-agent and MCP surfaces.
- JSONL replay batching, backoff, and structured import reports.
- Export to SIEM via webhook or JSONL.
- Basic installer and service wrapper.
- Native collector agents for Windows Event Log and Linux journald.
- CLA automation for pull requests.

Status: implemented in this repository.

## 3-6 Weeks: Beta

- Multi-tenant control plane.
- Organization-level RBAC policies.
- Policy packs.
- Deception token registry.
- Response approvals and execution export.
- Integration tests with replayed telemetry and Postgres-backed API smoke tests.
- Windows and Linux packaging.
- Better asset graph and investigation timeline.

Status: implemented in this repository.

## 6-10 Weeks: Production Candidate

- Hardening review.
- Threat model.
- Signed releases.
- Tamper-evident audit log export.
- Enterprise connectors.
- SSO/SAML for the commercial edition.
- Commercial license workflow.
- Documentation for deployment, operations, and incident response.

Status: implemented in this repository, including a full security audit with all
findings remediated and the host/CI deploy chain hardened (see
[hardening.md](hardening.md) and [threat-model.md](threat-model.md)).

## Product Positioning

Do not position this as another prompt-injection firewall. The strongest angle
is correlated defense against autonomous, tool-using adversaries across agent,
endpoint, network, deception, and response layers.
