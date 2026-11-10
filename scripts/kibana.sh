#!/usr/bin/env bash
set -euo pipefail
export KIBANA_PASSWORD="$(cat /state/kibana_system)"
export SAVED_OBJECTS_KEY="$(cat /state/saved_objects_key)"
export SESSION_KEY="$(cat /state/session_key)"
export REPORTING_KEY="$(cat /state/reporting_key)"
exec /usr/local/bin/kibana-docker
