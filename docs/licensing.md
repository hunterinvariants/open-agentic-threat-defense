# Licensing Model

Open Agentic Threat Defense uses AGPLv3-or-later plus a commercial dual-license
path.

## Community License

The community version is licensed under AGPL-3.0-or-later. This fits a control
plane because AGPL includes source-code obligations for network-service use.

## Commercial License

The commercial license path is for organizations that need to avoid AGPL
obligations or want enterprise terms, closed-source embedding, warranty,
support, or procurement language.

### Edition enforcement (license tokens)

Editions are enforced technically with Ed25519-signed license tokens. The vendor
generates a key pair and issues a token bound to an organization, edition,
feature set, and expiry (`oadtdctl license keygen | issue | verify`). A
deployment is configured with the public key (`--license-public-key`) and the
token (`--license-file`); the service verifies the signature and expiry on
startup and reports status at `GET /api/license`. With no token the service runs
as the community edition. The private key never ships with the product, so a
token cannot be forged without it. This is the technical edition gate; it is
independent of the AGPL/commercial legal licensing above.

## CLA From Day 1

External contributions require a CLA before merge so the project owner can keep
dual-licensing rights clean.

Required operational steps:

- keep a signed CLA record for every external contributor;
- block PR merge until the CLA is verified;
- enforce the CLA check in GitHub Actions using the PR template checkbox or the
  `cla-signed` label;
- preserve commit attribution;
- avoid accepting code copied from incompatible licenses;
- have counsel review the CLA before broad public contribution intake.

## Open Core Direction

Recommended split:

- open core: collectors, policy engine, correlator, local dashboard, safe
  telemetry simulator, basic response plans;
- commercial edition: SSO/SAML, RBAC, multi-tenancy, enterprise connectors,
  central policy distribution, compliance reports, managed rule packs, support.
