# Contributing

Open Agentic Threat Defense accepts contributions that improve defensive
visibility, policy enforcement, response automation, documentation, and safe
test coverage.

## CLA Required

Every external contributor must sign the project CLA before their work can be
merged. See [CLA.md](CLA.md).

Pull requests must include the CLA checkbox from the PR template. Maintainers
must verify the CLA record before merging.

## Safety Boundaries

Do not submit:

- exploit code;
- malware logic;
- autonomous propagation logic;
- credential theft tooling;
- instructions that enable unauthorized access.

Safe simulations are allowed when they generate telemetry only and cannot
spread, exploit, exfiltrate, or execute destructive actions.

## Development

Run the test suite:

```powershell
go test ./...
```

Run the local dashboard:

```powershell
go run ./cmd/oadtd --demo
```

Then open `http://localhost:8080`.

