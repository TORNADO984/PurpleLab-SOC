# Trace local archive staging

7-Zip creates an archive under Users\Public. Correlate process and file evidence while keeping collection separate from exfiltration.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1074.001, T1560.001. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario collection
docker compose run --rm lab validate --scenario collection
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **Archive creation in a public directory** (`df83bda3-25ba-59ed-8132-e59729f6a6a5`, T1560.001): An archive in a shared staging directory can precede transfer; it is not proof of exfiltration.
- **Archive file created in a public directory** (`1aed0717-2831-5548-9200-7ffc65d4b933`, T1074.001): File creation corroborates archive staging but not any subsequent transfer.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Inspect the 7z.exe command and identify source glob and archive output path. Do not open unknown archives.
2. Locate the Sysmon file creation event and compare file.path with the command's output path.
3. Record host/user/time and explain that a common path supports correlation but is weaker than a shared process entity.
4. Check approved support bundle or backup jobs, data classification and directory permissions.
5. Search for subsequent connections or file transfers using the same process/host. This scenario contains no transfer event, so exfiltration remains unproven.
6. Document the archive as staged data and request approved metadata/hash collection in a real incident. Avoid placing sensitive contents in the case ticket.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "collection" AND host.name: "win-lab-01"
(event.code: ("1" OR "11")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **Archive creation in a public directory**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\7z.exe) AND (process.command_line: * a * AND process.command_line: *\\Users\\Public\\*)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "1"
    }
  },
  {
    "wildcard": {
      "process.executable": {
        "value": "*\\\\7z.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "* a *",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*\\\\Users\\\\Public\\\\*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Archive file created in a public directory**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "11") AND (file.path: *\\Users\\Public\\*) AND (file.path: *.zip)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "11"
    }
  },
  {
    "wildcard": {
      "file.path": {
        "value": "*\\\\Users\\\\Public\\\\*",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "file.path": {
        "value": "*.zip",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- Support bundles and backups are often archived; verify source data, destination and authorized recipient.
- Approved support collections can use public folders; review permissions and retention.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

Escalate unapproved collection of sensitive data; do not label the case exfiltration without transfer evidence.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
