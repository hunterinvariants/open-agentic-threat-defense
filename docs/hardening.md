# Hardening Review

This document records the security hardening implemented in OADTD and the
operator checklist for a hardened deployment. It complements
[threat-model.md](threat-model.md).

## 1. Implemented hardening

### Application / API
- **Secure by default:** the service refuses to bind a non-loopback address
  without authentication unless `--insecure` is set.
- **HTTP server timeouts:** `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`,
  `IdleTimeout` set (Slowloris / slow-client protection) plus graceful shutdown.
- **Login rate limiting:** per-source exponential backoff with `Retry-After`,
  backed by Postgres so the lockout is global across HA instances.
- **Security headers:** strict `Content-Security-Policy` (`script-src 'self'`),
  `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`.
- **Audit source IP** from `X-Forwarded-For` is trusted only behind a configured
  `--trusted-proxies` CIDR; cookies marked `Secure` when TLS is terminated by a
  trusted proxy (`X-Forwarded-Proto`).
- **Retention:** events/alerts/actions/audits pruned by a configurable window.

### AuthN / AuthZ / multi-tenancy
- Constant-time token comparison; SHA-256 token hashes only (no plaintext).
- RBAC on every API path; high-impact response actions are approval-gated.
- **Session signing key required:** `OATD_SESSION_SECRET` is mandatory when auth
  or SSO is configured (no insecure derivation fallback).
- OIDC: JWKS RS256 verification, `iss`/`aud`/`exp`/`nonce` checks, signed-state
  CSRF protection, `alg=none` rejected. SAML: assertion signature verified via
  goxmldsig, gated behind `RequireAccount`, explicit SP key/cert required.
- Tenant is derived from the verified principal only; every store path is
  tenant-scoped; IdP-asserted tenants are checked against an allowlist.

### Inline gateway / SSRF
- Gateway-proxy upstream is validated (scheme + blocklist for loopback,
  link-local, private, multicast, cloud-metadata) and **IP-pinned at dial time**
  to defeat DNS rebinding; forwarded headers are allowlisted; upstream response
  bodies are size-capped.
- MCP proxy defaults to *intercept* (only `initialize`/`ping`/notifications pass
  through); denied calls never reach the upstream.

### Audit integrity
- SHA-256 hash chain `H(prev || record)`; chain head shared in Postgres via
  `SELECT ... FOR UPDATE` (no fork across HA instances); **HMAC-anchored** with a
  server-held key (`OATD_AUDIT_HMAC_SECRET`); snapshot reports `unlinked` and
  marks `valid:false` when records sit outside the anchored chain.

### Supply chain / CI
- All third-party GitHub Actions pinned to commit SHAs; CodeQL, Dependabot
  (gomod + actions), and dependency-review enabled; release SBOM + checksums
  (signing available via cosign).

### Packaging
- systemd units with `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`,
  `ProtectHome`, `ReadWritePaths`; secrets passed via `EnvironmentFile`, **not**
  on the `ExecStart` command line; nginx terminates TLS and sets
  `X-Forwarded-Proto https`.

## 2. Operator hardening checklist

Set before exposing the service:

- [ ] `OATD_SESSION_SECRET` — 32+ random bytes (required with auth/SSO).
- [ ] `OATD_AUDIT_HMAC_SECRET` — dedicated key for the audit anchor (do not reuse
      the session secret).
- [ ] `--trusted-proxies` — CIDR of your TLS-terminating proxy/LB.
- [ ] TLS terminated (nginx 443 config or external LB) with `X-Forwarded-Proto`.
- [ ] Users defined in the policy file with token hashes, or SSO configured —
      never run a non-loopback listener without auth (or `--insecure`).
- [ ] `--retention-window` set to your retention policy (e.g. `720h`).
- [ ] Postgres credentials least-privilege; `sslmode=require` to the DB.
- [ ] systemd unit installed from `packaging/systemd/`; secrets in
      `/etc/oadtd/<instance>.env` (mode 0600).
- [ ] Self-hosted runner (if used) on an isolated host; deploy SSH key scoped.

## 3. Residual items / recommendations

- Audit chain is tamper-evident, not tamper-proof — add an external append-only
  anchor (e.g. periodic head export to a WORM/notary) for strong non-repudiation.
- Detection engine is heuristic — track false-positive rates and consider
  structured/ML detections for the highest-value rules.
- Postgres is the HA SPOF — use a managed/replicated Postgres for real HA.
- Tighten systemd further (`ProtectSystem=strict`, `SystemCallFilter`,
  `RestrictAddressFamilies`, `CapabilityBoundingSet=`) for high-assurance hosts.
