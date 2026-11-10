# Usage and evidence

## CLI

```sh
docker compose run --rm lab list
docker compose run --rm generator generate --scenario persistence
docker compose run --rm generator generate --scenario all --negative
docker compose run --rm lab validate --scenario persistence --timeout 300
```

`generator` mounts only ingestion credentials. The administrative `lab` service supports provisioning, validation and credential display. Use it only as the Docker lab administrator. No CLI command executes fixture process command lines.

Offline inspection requires Python but no credentials or network:

```sh
python -m purplelab generate --scenario execution --dry-run
python scripts/export_events.py execution artifacts/events/execution.ndjson
```

Supported scenario names: `execution`, `credential-access`, `persistence`, `discovery`, `lateral-movement`, `defense-evasion`, `command-and-control`, `collection`, or `all`.

## Validation contract

Each validation ingests positive and benign near-miss fixtures with a new run ID. It queries the actual Security alert index, requires the intended rule UUID and source event UUID, rejects any PurpleLab alert on a negative control, waits at least 90 seconds, and requires successful scheduled rule executions after ingestion. Authorization errors, partial ingestion and truncated alert searches fail the run. Timeouts return a nonzero exit and list missing rules.

This is a bounded check of the current fixtures and rule schedule. It is not proof that every future benign event is safe. Negative controls are not a representative enterprise baseline. Historical alerts and matching raw events cannot make a new run pass.

Store sanitized JSON output as case evidence. Run outcomes also appear in `purplelab-validation` and the coverage dashboard. A failed suite marks its selected per-rule outcomes failed conservatively; review the detailed report to distinguish missing positives, execution faults and negative matches.

## Kibana

Open the default space, then **Dashboards**:

- **PurpleLab • Detection coverage** shows observed alerts by exercise ATT&CK label and validation outcomes. A missing technique means unobserved, not covered.
- **PurpleLab • Event timeline** combines saved event and alert searches.
- **PurpleLab • Scenario investigation** shows scenario activity and evidence searches.

In **Discover**, select `PurpleLab events` and filter source events with:

```text
purplelab.run_id: "<RUN_ID>"
```

In **Security → Alerts**, filter the corresponding indexed alert tags:

```text
tags: "purplelab-run-<RUN_ID>"
```

Use UTC and the last 15 minutes. Real Windows events do not carry synthetic scenario/run/technique labels; investigate them using host, user, process, event code and time. Their alerts remain visible in the alerts table, but synthetic technique charts cannot assign exercise labels to them.

## Optional Filebeat

```sh
python scripts/export_events.py discovery artifacts/events/discovery.ndjson
docker compose --profile filebeat up -d filebeat
docker compose logs --tail 30 filebeat
```

Filebeat reads only `artifacts/events/*.ndjson`, not host system logs. The default pipeline normalizes raw Windows fields and preserves ECS values. Export fresh events; reference fixtures contain fixed timestamps and will be outside the rule lookback. Do not ingest the same event IDs through both direct bulk and Filebeat during a validation run. The Filebeat healthcheck validates configuration; output logs and indexed event counts establish delivery.

## Retention and cleanup

Events are deleted after seven days based on index age. Alerts and validation evidence are not covered by that event ILM policy. Export evidence before resetting. `docker compose down` preserves volumes. `python scripts/cleanup.py --purge` asks for `PURGE` and deletes only this Compose project's volumes. Do not run a global Docker prune.
