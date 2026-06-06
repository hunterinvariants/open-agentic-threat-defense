# Roadmap

## Hours: MVP

- Safe demo telemetry.
- Policy engine.
- Correlation engine.
- Dry-run response planner.
- Local dashboard.
- AGPLv3-or-later plus commercial dual-license path.
- CLA requirement from day 1.

Status: implemented in this repository.

## 1-2 Weeks: Alpha

- Durable SQLite or Postgres storage.
- Authenticated API.
- Configurable policies.
- Signed tool manifests for AI-agent and MCP surfaces.
- Collector adapters for Sysmon, auditd, Zeek, Suricata, and proxy logs.
- Export to SIEM via webhook or JSONL.
- Basic installer and service wrapper.
- CLA automation for pull requests.

## 3-6 Weeks: Beta

- Multi-tenant control plane.
- RBAC.
- Policy packs.
- Deception token registry.
- Response approvals.
- Integration tests with replayed telemetry.
- Windows and Linux packaging.
- Better asset graph and investigation timeline.

## 6-10 Weeks: Production Candidate

- Hardening review.
- Threat model.
- Signed releases.
- Audit logging.
- Enterprise connectors.
- SSO/SAML for the commercial edition.
- Commercial license workflow.
- Documentation for deployment, operations, and incident response.

## Product Positioning

Do not position this as another prompt-injection firewall. The strongest angle
is correlated defense against autonomous, tool-using adversaries across agent,
endpoint, network, deception, and response layers.

