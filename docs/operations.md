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

## Storage

Current durable storage is the local JSON snapshot configured with `--data`.
This is suitable for local labs, pilots, and single-node testing.

SQLite/Postgres is the next storage milestone. It should be implemented behind
the existing store boundary so the API and collectors do not change when the
storage backend changes.

