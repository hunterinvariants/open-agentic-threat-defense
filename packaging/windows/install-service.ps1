param(
  [string]$BinaryPath = "C:\Program Files\OATD\oadtd.exe",
  [string]$WorkingDirectory = "C:\ProgramData\OATD",
  [string]$PolicyPath = "C:\ProgramData\OATD\policy.json",
  [string]$DataPath = "C:\ProgramData\OATD\state.json",
  [string]$ListenAddress = ":8080",
  [string]$ServiceName = "OATD"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $BinaryPath)) {
  throw "Binary not found: $BinaryPath"
}

New-Item -ItemType Directory -Force -Path $WorkingDirectory | Out-Null

$arguments = "--addr $ListenAddress --data `"$DataPath`""
if (Test-Path -LiteralPath $PolicyPath) {
  $arguments = "$arguments --policy `"$PolicyPath`""
}

$binPath = "`"$BinaryPath`" $arguments"

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
  sc.exe stop $ServiceName | Out-Null
  sc.exe delete $ServiceName | Out-Null
  Start-Sleep -Seconds 2
}

sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "Open Agentic Threat Defense" | Out-Null
sc.exe description $ServiceName "Defensive control plane for agentic threat telemetry, policy, and response planning." | Out-Null
sc.exe start $ServiceName | Out-Null

Write-Host "Installed and started service $ServiceName"

