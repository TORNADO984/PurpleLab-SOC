param([switch]$Purge)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if ($Purge) {
  if ((Read-Host 'Type PURGE to destroy this lab evidence and credentials') -cne 'PURGE') { exit 1 }
  docker compose --profile tools --profile filebeat down --volumes --remove-orphans
} else {
  docker compose --profile tools --profile filebeat down --remove-orphans
}
exit $LASTEXITCODE
