# Triage credential access indicators

A diagnostic process requests extensive LSASS access while reg.exe exports the SAM hive. Determine whether this is approved forensic collection.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1003.001, T1003.002. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario credential-access
docker compose run --rm lab validate --scenario credential-access
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **Unusual LSASS process access** (`386c5daa-b277-5844-a68d-60c199980ce4`, T1003.001): High access masks against LSASS can indicate credential access. This does not prove a dump occurred.
- **SAM registry hive export** (`7f86ae50-a0d9-5a79-9a62-7dc8b20267f5`, T1003.002): Exporting SAM can expose local password hashes; correlate with SYSTEM hive access.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Review Sysmon event 10 and copy SourceImage/TargetImage (or mapped process.executable) and GrantedAccess into the case record.
2. Confirm the target is lsass.exe and the mask is 0x1fffff. A handle request alone does not establish that credentials were extracted.
3. Search the same host for reg.exe and SAM export. Record destination paths without opening any potentially sensitive output.
4. Check the actor's authorization, process signing evidence and forensic collection ticket. The fixture omits signing evidence deliberately.
5. Request process tree, file creation and SYSTEM hive access evidence for a real case; list these as unknown if not available.
6. For a confirmed unauthorized real action, escalate to the incident lead for isolation and credential rotation under the approved response procedure.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "credential-access" AND host.name: "win-lab-01"
(event.code: ("10" OR "1")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **Unusual LSASS process access**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "10") AND (winlog.event_data.TargetImage: *\\lsass.exe) AND (winlog.event_data.GrantedAccess: "0x1fffff" OR winlog.event_data.GrantedAccess: "0x1f0fff")
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "10"
    }
  },
  {
    "wildcard": {
      "winlog.event_data.TargetImage": {
        "value": "*\\\\lsass.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "bool": {
      "should": [
        {
          "term": {
            "winlog.event_data.GrantedAccess": "0x1fffff"
          }
        },
        {
          "term": {
            "winlog.event_data.GrantedAccess": "0x1f0fff"
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
]
```

KQL equivalent for investigation of **SAM registry hive export**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\reg.exe) AND (process.command_line: *save* AND process.command_line: *HKLM\\SAM*)
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
        "value": "*\\\\reg.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*save*",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*HKLM\\\\SAM*",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- EDR and approved diagnostic tools may access LSASS; corroborate signature, owner and access mask.
- Authorized forensic acquisition may export hives; require a case number and explicit host approval.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

High severity if unapproved access is corroborated; do not claim that password dumping succeeded from these events alone.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
