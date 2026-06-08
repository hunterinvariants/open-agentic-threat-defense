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
- **Request body limits:** all mutating requests (`POST`/`PUT`/`PATCH`) are capped
  at 4 MiB by middleware so an oversized body cannot drive proportional allocation
  through the JSON decoders; the ingest and MCP paths cap further at 1 MiB.
- **Login rate limiting:** per-source exponential backoff with `Retry-After`,
  backed by Postgres so the lockout is global across HA instances.
- **Security headers:** strict `Content-Security-Policy` (`script-src 'self'`, no
  inline scripts, `object-src 'none'`, `frame-ancestors 'none'`, `frame-src
  'none'`, `form-action 'self'`), `X-Content-Type-Options`, `X-Frame-Options:
  DENY`, `Referrer-Policy`. Dashboard `innerHTML` sinks escape every interpolated
  telemetry field.
- **Error hygiene:** `500` responses return a generic message and log the detail
  server-side (no DB schema/SQL/driver diagnostics leaked to clients); control
  characters are stripped from logged user-influenced strings (log injection).
- **Audit source IP** from `X-Forwarded-For` is trusted only behind a configured
  `--trusted-proxies` CIDR; cookies marked `Secure` when TLS is terminated by a
  trusted proxy (`X-Forwarded-Proto`).
- **Retention:** events/alerts/actions/audits pruned by a configurable window;
  the destructive rewrite runs only when records actually age out (no per-write
  table rewrite).

### AuthN / AuthZ / multi-tenancy
- Constant-time token comparison; SHA-256 token hashes only (no plaintext).
- RBAC on every API path (the central `RequiredRoles` table is the single source
  of truth, including for admin-only `GET`s); high-impact response actions are
  approval-gated.
- **Session revocation:** sessions carry a random id (`jti`); logout records it in
  a server-side revocation denylist that session validation checks, and an
  absolute max-age is enforced from issuance — a captured cookie is invalidated
  the moment its owner logs out. (Denylist is per-instance; see §3.)
- **Session signing key required:** `OATD_SESSION_SECRET` is mandatory when auth
  or SSO is configured (no insecure derivation fallback).
- **SSO role allowlist:** IdP-asserted roles/groups are filtered to the known
  application role set, so an injected or unmapped role string cannot grant
  access.
- OIDC: JWKS RS256 verification; `iss`/`aud`/`exp`/`nonce` checks; `azp` required
  to equal `client_id` for multi-audience tokens; issuer and discovered
  endpoints must be HTTPS (plain `http` only for loopback); signed-state CSRF
  protection; `alg=none` rejected. SAML: assertion signature verified via
  goxmldsig (patched, see §1 supply chain), gated behind `RequireAccount`.
- Tenant is derived from the verified principal only; every store path is
  tenant-scoped; IdP-asserted tenants are checked against an allowlist.
- **Tenant administration is scoped:** a platform admin (admin in the default
  tenant) may manage any tenant; other admins may manage only their own tenant or
  one where they are listed in `Admins` — not a global wildcard.
- **Assets are tenant-keyed** by `(tenant, id)` in memory and as the Postgres
  primary key, so two tenants sharing an asset id cannot collide.

### Inline gateway / SSRF
- Gateway-proxy upstream is validated (scheme + blocklist for loopback,
  link-local, private, multicast, cloud-metadata, **RFC 6598 CGNAT**, and reserved
  ranges) and **IP-pinned at dial time** to defeat DNS rebinding; forwarded
  headers are allowlisted; upstream response bodies are size-capped.
- **Local/internal upstreams are an explicit operator opt-in**
  (`--proxy-allow-local-targets`, off by default) — never inferred from the TCP
  peer address, so a same-host reverse proxy does not unlock SSRF for all callers.
- The proxy and MCP-proxy endpoints are refused when authentication is not
  configured (no unauthenticated internal-request vector in open mode).
- Userinfo credentials embedded in an upstream URL are stripped before the URL is
  written to audit/action metadata (CWE-532).
- The obfuscation matcher peels multiple encoding layers (base64-of-base64) and
  decodes hex, so double-encoding does not evade detection.
- MCP proxy defaults to *intercept* (only `initialize`/`ping`/notifications pass
  through); denied calls never reach the upstream; org-scoped policy overlays are
  enforced on the MCP path too.
- **Backpressure** is a per-instance in-process semaphore that sheds with `429`
  when the in-flight cap is reached — it does not pin a database connection per
  request (no pool-exhaustion deadlock).

### Audit integrity
- SHA-256 hash chain `H(prev || record)`; chain head shared in Postgres via
  `SELECT ... FOR UPDATE` (no fork across HA instances).
- **Validity is re-derived from the event rows at runtime** in the Postgres path
  (every record hash recomputed, `PrevHash` links walked, head/anchor compared) —
  DB tampering of a non-head record is detected live, not trusted from a stored
  flag.
- **HMAC-anchored** with a server-held key (`OATD_AUDIT_HMAC_SECRET`); when only
  `OATD_SESSION_SECRET` is set, the audit key is **derived from it via a labelled
  HMAC** (domain-separated), not reused raw.
- Snapshot reports `unlinked` and marks `valid:false` when records sit outside the
  anchored chain.

### Threat-pack integrity
- Threat-pack manifests are HMAC-signable; when a signing key is configured,
  verification **fails closed** on a missing or invalid signature (a missing
  `.sig` no longer silently skips verification), and an unsigned load with no key
  is warned.

### Supply chain / CI
- All third-party GitHub Actions pinned to commit SHAs (including `setup-go`);
  CodeQL, Dependabot (gomod + actions), and dependency-review enabled.
- `release.yml` runs at `contents: read`, granting `id-token: write` +
  `contents: write` only to the publish job; CI/release have concurrency groups.
- Release publishes an SBOM and a `SHA256SUMS` manifest covering binaries **and**
  the SBOM, signed with Sigstore keyless signing; the `cosign verify-blob`
  invocation is documented in the README.
- Dependencies kept patched: `goxmldsig` ≥ 1.6.0 (clears the SAML
  signature-validation bypass), Go toolchain pinned to 1.25.11 (clears the
  reachable stdlib advisories), `golang.org/x/crypto` current.
- Hand-rolled collector/JSONL parsers have fuzz harnesses (`go test -fuzz`).

### Packaging / host
- systemd units run as a dedicated non-root user, bind `127.0.0.1` only, and apply
  a full sandbox: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, kernel/clock/hostname/proc protections,
  `RestrictAddressFamilies`, `RestrictNamespaces`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet`, `UMask=0077`,
  resource limits. Secrets are passed via `EnvironmentFile` (mode `0600`), never on
  `ExecStart`. (`systemd-analyze security` ≈ 1.5 / OK.)
- **Self-hosted runner runs as a non-root user** and may `sudo` only a single
  fixed, root-owned deploy wrapper (`/usr/local/sbin/oadtd-deploy`) — not
  arbitrary `install`/`rm`/`chown`/`systemctl`. A build-time supply-chain
  compromise is confined to the unprivileged runner user; the deploy ref is
  allowlisted to `main`/`vX.Y.Z`.

## 2. Operator hardening checklist

Set before exposing the service:

- [ ] `OATD_SESSION_SECRET` — 32+ random bytes (required with auth/SSO).
- [ ] `OATD_AUDIT_HMAC_SECRET` — dedicated key for the audit anchor (recommended;
      otherwise a domain-separated key is derived from the session secret).
- [ ] `--trusted-proxies` — CIDR of your TLS-terminating proxy/LB.
- [ ] TLS terminated (nginx 443 config or external LB) with `X-Forwarded-Proto`.
- [ ] Users defined in the policy file with token hashes, or SSO configured —
      never run a non-loopback listener without auth (or `--insecure`).
- [ ] `--retention-window` set to your retention policy (e.g. `720h`).
- [ ] Postgres credentials least-privilege; `sslmode=require` to the DB.
- [ ] systemd unit installed from `packaging/systemd/` (binds loopback + full
      sandbox); secrets in `/etc/oadtd/<instance>.env` (mode 0600); reach the UI
      via reverse proxy or SSH tunnel.
- [ ] `OATD_MANIFEST_HMAC_SECRET` set if you load a custom threat pack (signing
      then fails closed).
- [ ] Self-hosted runner (if used) runs as a non-root user behind the deploy
      wrapper (`scripts/setup-self-hosted-runner.sh`); host firewalled.
- [ ] `--proxy-allow-local-targets` left off unless you deliberately proxy to
      internal hosts.

## 3. Residual items / recommendations

- **Audit chain is tamper-evident, not tamper-proof.** Runtime re-derivation
  detects record tampering, but the HMAC key lives on the host; an attacker with
  both DB write and host env access can still rewrite the chain consistently. Add
  an external append-only anchor (periodic head export to a WORM/notary) for
  strong non-repudiation. The anchor HMAC binds the head/index/validity, and the
  audit-event hash does not yet include the `tenant` field — both are candidates
  for a future chain-format version bump.
- **Session revocation is per-instance.** The denylist is in-memory, so in an HA
  deployment a logout revokes only on the instance that served it; the absolute
  max-age still bounds every session globally. A shared revocation store would
  make revocation cluster-wide.
- **Detection is heuristic.** The policy/risk engine uses obfuscation-resistant
  term/taint co-occurrence + risk scoring + history, not data-flow analysis or
  ML. It can produce false positives and is evadable by a determined adversary.
- **Postgres is the HA single point of failure.** HA is app-tier redundancy only;
  use a managed/replicated Postgres for real HA.
- **Demo tool backend is a stub.** Real MCP/tool integration is required for
  production enforcement of actual tool effects.
- **Un-bypassability is a deployment property.** Enforcement only holds if the
  agent's only path to tools is through the gateway/MCP proxy.
