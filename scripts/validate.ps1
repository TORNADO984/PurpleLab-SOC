$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose run --rm lab validate @args
exit $LASTEXITCODE
