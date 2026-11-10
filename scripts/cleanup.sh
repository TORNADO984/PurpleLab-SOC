#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--purge" ]; then
  read -r -p 'Type PURGE to destroy this lab evidence and credentials: ' answer
  [ "$answer" = PURGE ] || exit 1
  docker compose --profile tools --profile filebeat down --volumes --remove-orphans
else
  docker compose --profile tools --profile filebeat down --remove-orphans
fi
