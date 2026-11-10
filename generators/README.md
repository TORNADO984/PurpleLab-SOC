# Synthetic event generators

The implementation is in `purplelab/events.py`; this directory holds reviewable positive and negative reference fixtures. Fixture command lines are data, never executed.

```sh
docker compose run --rm generator generate --scenario execution
docker compose run --rm generator generate --scenario all --negative
python -m purplelab generate --scenario discovery --dry-run
python scripts/export_events.py collection artifacts/events/collection.ndjson
```

Every live run gets fresh UTC timestamps, event UUIDs and a run UUID. Events include ECS, original Windows fields, synthetic labels and ATT&CK exercise metadata. Native rule queries do not inspect exercise labels. The file fixtures have fixed reference timestamps; use the generator to produce current events.

Supported Sysmon IDs: 1, 3, 10, 11, 13, 22. Security: 4624, 4698, 1102. System: 7045. This is a selected telemetry model, not a full Windows event emulator. Neither generators nor setup execute any attack or modify host security settings.
