$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose up -d
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'Wait for provisioning: docker compose logs -f provision'
Write-Host 'Credentials: docker compose run --rm --no-deps lab credentials'
