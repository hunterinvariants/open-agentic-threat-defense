# Threat Model

This document is the threat model for Open Agentic Threat Defense (OADTD). It
describes what the system protects, the trust boundaries, the threats considered,
the mitigations in place, and the residual risks that operators must account for.

## 1. System overview

OADTD is a defensive control plane for agentic threat behavior. Its security-
relevant components are:

- **Ingest API** (`/api/events`) — accepts telemetry from collectors/replay.
- **Inline tool-call gateway** (`/api/gateway/decide`, `/api/gateway/execute`,
  MCP proxy) — a Policy Enforcement Point that allows / holds-for-approval /
  blocks agent tool calls *before* execution.
- **Policy + correlator + risk engine** — the decision logic.
- **Store** (Postgres in production, JSON snapshot for dev) — events, alerts,
  response actions, audit chain, tenants.
- **AuthN/AuthZ** — token + session auth, RBAC, OIDC/SAML SSO, multi-tenant
  isolation.
- **Audit chain** — HMAC-anchored, tamper-evident audit log.
- **Outbound connectors** — alert/ticket/response webhooks, GitHub, MCP upstream.

## 2. Assets to protect

| Asset | Why it matters |
|---|---|
| Integrity of enforcement decisions | A bypass lets a malicious agent act. |
| Audit log integrity | Forensic/compliance value; must resist tampering. |
| Tenant data isolation | One tenant must never read/write another's data. |
| Secrets | Session key, audit HMAC key, DSNs, SSO secrets, connector tokens. |
| Availability of the gateway | It sits in the agent's critical path. |

## 3. Trust boundaries

1. **Untrusted → Ingest/Gateway:** event submitters and agent tool calls are
   attacker-influenceable. All fields are treated as untrusted input.
2. **Authenticated client → API:** authenticated principals are bounded by RBAC
   and by their tenant (derived from the verified session, never from client
   input).
3. **OATD → outbound connectors:** destination URLs are operator-configured;
   the client-supplied gateway-proxy upstream is validated and IP-pinned.
4. **OATD → datastore:** the store is trusted for availability but the audit
   chain is designed to detect DB-level tampering (see limitations).

## 4. Threat actors

- **Malicious / compromised AI agent** — tries to exfiltrate secrets, touch
  decoys, or run unapproved tools through the gateway.
- **Authenticated low-privilege user** — tries privilege escalation, cross-tenant
  access, or SSRF via the gateway proxy.
- **Network attacker** — tries to read traffic or spoof source identity.
- **DB-level attacker** — has write access to Postgres and tries to rewrite
  history/audit.

## 5. Threats and mitigations (STRIDE-oriented)

- **Spoofing:** session cookies are HMAC-signed and carry a `jti` that logout
  revokes server-side (plus an absolute max-age); tokens compared in constant
  time; SSO ID tokens verified (JWKS RS256, iss/aud/exp/nonce, `azp` for
  multi-audience, HTTPS-only issuer/endpoints); SAML assertions verified via
  patched goxmldsig; IdP-asserted roles filtered to the known role set; audit
  `source_ip` from `X-Forwarded-For` only behind a configured trusted proxy.
- **Tampering:** audit chain is `H(prev || record)` SHA-256, HMAC-anchored with a
  server-held (domain-separated) key; in the Postgres path validity is
  **re-derived from the event rows at runtime** so non-head DB tampering is
  detected live; `valid:false` + `unlinked` surfaced when records sit outside the
  chain. (Residual: see §6.)
- **Repudiation:** every gateway decision, approval, login, and ingest is an
  audit record with actor, roles, source, and outcome.
- **Information disclosure:** RBAC on all endpoints; tenant-scoped store access;
  `LastPersistenceError` redacted; secrets read from env, never logged, never on
  the process command line.
- **Denial of service:** HTTP server timeouts (Slowloris); per-IP login
  rate-limit (Postgres-backed across HA); gateway in-flight limiter (per-instance
  in-process semaphore that sheds `429` without pinning a DB connection — no
  pool-exhaustion deadlock); mutating request bodies capped at 4 MiB; the
  correlator scans only the most recent events per ingest; retention prune runs
  only when records age out.
- **Elevation of privilege:** secure-by-default (refuses non-loopback bind
  without auth); RBAC roles (central `RequiredRoles` table authoritative);
  approval-gated high-impact actions; tenant from the verified principal only;
  IdP-asserted tenant checked against an allowlist and IdP roles against the known
  role set; tenant administration scoped to platform admins or the caller's own
  tenant (no global wildcard).
- **SSRF:** gateway-proxy upstream validated (scheme, host/IP blocklist for
  loopback/link-local/private/metadata/RFC6598/reserved) and **IP-pinned** at dial
  time to defeat DNS rebinding; local/internal upstreams are an explicit operator
  opt-in (never inferred from the peer address); proxy endpoints refused in open
  mode; forwarded headers allowlisted; URL userinfo stripped from logs; upstream
  response size-capped.

## 6. Known limitations / residual risk

- **Audit chain is tamper-*evident*, not tamper-*proof*.** Runtime re-derivation
  detects record tampering, but the HMAC key lives on the host; an attacker with
  both DB write and host env access can still rewrite the chain consistently. True
  non-repudiation needs an external append-only anchor. The anchor binds the
  head/index/validity and the audit-event hash does not yet cover the `tenant`
  field — both warrant a future chain-format version bump.
- **Session revocation is per-instance.** Logout revokes server-side via an
  in-memory `jti` denylist; in HA this is local to the serving instance, though
  the absolute max-age still bounds every session globally.
- **Detection is heuristic.** The policy/risk engine uses obfuscation-resistant
  term/taint co-occurrence + risk scoring + history, not data-flow analysis or
  ML. It can produce false positives and is evadable by a determined adversary.
- **Postgres is the HA single point of failure.** HA is app-tier redundancy only.
- **Demo tool backend is a stub.** Real MCP/tool integration is required for
  production enforcement of actual tool effects.
- **Un-bypassability is a deployment property.** Enforcement only holds if the
  agent's only path to tools is through the gateway/MCP proxy.

## 7. Out of scope

Host/OS compromise with root and physical access are out of scope. Supply-chain
compromise of dependencies is mitigated separately (SHA-pinned actions, CodeQL,
Dependabot, dependency-review, fuzzed parsers, patched crypto/XML deps) and its
blast radius is reduced: the self-hosted CI runner runs as a non-root user and
may `sudo` only a fixed deploy wrapper, so build-time code execution is confined
to the unprivileged runner account rather than root.
