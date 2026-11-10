#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose up -d
echo 'Wait for provisioning: docker compose logs -f provision'
echo 'Credentials: docker compose run --rm --no-deps lab credentials'
