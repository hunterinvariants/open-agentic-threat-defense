# Security Policy

Open Agentic Threat Defense (OADTD) is defensive security software. Reports
about vulnerabilities in this project are welcome and handled under coordinated
disclosure.

## Supported versions

Security fixes land on `main` and ship in the next tagged release. The most
recent minor release line receives security updates.

| Version | Supported |
|---|---|
| `0.2.x` (latest) | ✅ |
| `< 0.2` | ❌ |

## Reporting a vulnerability

**Please report privately — do not open a public issue for a security bug.**

- Preferred: use GitHub's private vulnerability reporting on this repository —
  **Security → Report a vulnerability** ("Report a vulnerability" button on the
  repo's Security tab). This opens a private advisory thread with the maintainer.
- If private reporting is unavailable to you, open a minimal public issue that
  says only "security report — please enable private reporting / provide a
  contact" without any exploit detail, and wait for a private channel.

Include where possible:

- affected version or commit SHA;
- impact and the trust boundary crossed (see [docs/threat-model.md](docs/threat-model.md));
- reproduction steps or a proof of concept;
- affected configuration (auth mode, multi-tenancy, SSO, connectors);
- suggested mitigation, if known.

### Coordinated disclosure timeline

- **Acknowledgement:** within 3 business days.
- **Triage + severity assessment:** within 7 business days, using CVSS-style
  reasoning and the trust boundaries in the threat model.
- **Fix target:** Critical/High as soon as practical (typically ≤ 14 days), with
  a private patch and, where warranted, a GitHub Security Advisory + CVE.
- **Disclosure:** coordinated with the reporter after a fix is available;
  reporters are credited unless they prefer to remain anonymous.

Please give us a reasonable window to remediate before public disclosure.

## Scope

In scope:

- vulnerabilities in the server/API, inline gateway/PEP, policy & risk engine,
  audit chain, multi-tenancy isolation, SSO (OIDC/SAML), or the dashboard;
- authentication/authorization bypass, cross-tenant data access, SSRF, injection,
  privilege escalation;
- unsafe default behavior or secrets handling;
- response actions that could exceed dry-run or configured permissions;
- supply-chain weaknesses in the build/release/deploy workflows.

Out of scope:

- requests for offensive features or exploit development;
- live-target testing without authorization;
- findings that require host/OS root or physical access (see the threat model);
- the demo/stub tool backend, which is intentionally not a real execution path;
- best-practice suggestions with no demonstrable security impact.

## Security model and hardening

The system's trust boundaries, threats, mitigations, and residual risks are
documented in:

- [docs/threat-model.md](docs/threat-model.md) — STRIDE-oriented threat model.
- [docs/hardening.md](docs/hardening.md) — implemented hardening + an operator
  hardening checklist.

Deploy with authentication configured, a non-loopback listener fronted by TLS,
`OATD_SESSION_SECRET` and a dedicated `OATD_AUDIT_HMAC_SECRET` set, and the
packaged sandboxed systemd unit. The service is secure-by-default: it refuses to
bind a non-loopback address without authentication unless `--insecure` is set.

## Verifying releases

Tagged releases publish platform binaries, an SPDX SBOM (`SBOM.spdx.json`), and a
`SHA256SUMS` manifest covering the binaries and the SBOM. The manifest is signed
with **Sigstore keyless signing** (no long-lived key); the signature bundle is
`SHA256SUMS.bundle`. Verify provenance and integrity before trusting a download:

```bash
# 1) Fetch the artifacts (replace vX.Y.Z with the release tag)
base=https://github.com/hunterinvariants/open-agentic-threat-defense/releases/download/vX.Y.Z
curl -sLO "$base/SHA256SUMS"
curl -sLO "$base/SHA256SUMS.bundle"
curl -sLO "$base/oadtd-linux-amd64"   # plus any other artifacts you use

# 2) Verify the manifest signature was produced by this repo's release workflow
cosign verify-blob \
  --bundle SHA256SUMS.bundle \
  --certificate-identity "https://github.com/hunterinvariants/open-agentic-threat-defense/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
#   expected: Verified OK

# 3) Verify your downloaded artifacts against the now-trusted manifest
sha256sum -c SHA256SUMS 2>/dev/null | grep -E 'oadtd|SBOM'

# 4) (optional) Confirm the binary reports the expected version
chmod +x oadtd-linux-amd64
timeout 2 ./oadtd-linux-amd64 --addr 127.0.0.1:0 --demo 2>&1 | grep -o 'Threat Defense [0-9.]*'
```

`Verified OK` proves the checksum manifest was signed by this repository's
`release.yml` workflow at that tag (keyless, via the Sigstore certificate chain
and the Rekor transparency log) — no private key exists to be stolen.

## Supply-chain assurances

- All third-party GitHub Actions are pinned to commit SHAs.
- CodeQL, Dependabot (Go modules + Actions), and dependency-review run on PRs.
- Security-sensitive dependencies and the Go toolchain are kept patched; the
  hand-rolled telemetry parsers have fuzz harnesses.
- The self-hosted deploy runner runs as a non-root user and may `sudo` only a
  fixed, root-owned deploy wrapper, confining a build-time compromise to an
  unprivileged account.
