# Review three persistence mechanisms

An endpoint adds an AppData Run key, creates a PowerShell task, and installs a service under a shared writable directory.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1053.005, T1543.003, T1547.001. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario persistence
docker compose run --rm lab validate --scenario persistence
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **Run key points into a user profile** (`b5a789cb-63da-5dbc-969a-5e2629a221f3`, T1547.001): User-writable autorun targets can provide persistence.
- **Scheduled task invokes PowerShell** (`724d23f6-b801-519d-a6be-dfe2aa981049`, T1053.005): PowerShell scheduled execution warrants examination of the complete task XML.
- **Service installed from a writable path** (`6827f56b-d089-5a6d-8667-649742b792cf`, T1543.003): A service executable in a shared writable directory creates a persistence opportunity.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Identify each of the three alerts and order them by @timestamp. Record user and host context independently for each.
2. Read registry.path and Details. Determine which account owns the Run key and whether its executable directory is writable.
3. Inspect TaskName and TaskContent as text. Extract the command; request complete trigger, principal and author fields in a real investigation.
4. Inspect service name and ImagePath. Compare the binary path to authorized software inventory and expected file permissions.
5. Search for execution of the referenced paths after registration. The synthetic scenario demonstrates registration only, so absence of execution does not prove removal.
6. Document an approval or escalation decision for each mechanism. In a real response, preserve configuration and binary evidence before approved removal.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "persistence" AND host.name: "win-lab-01"
(event.code: ("13" OR "4698" OR "7045")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **Run key points into a user profile**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "13") AND (registry.path: *\\CurrentVersion\\Run\\*) AND (winlog.event_data.Details: *\\AppData\\*)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "13"
    }
  },
  {
    "wildcard": {
      "registry.path": {
        "value": "*\\\\CurrentVersion\\\\Run\\\\*",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "winlog.event_data.Details": {
        "value": "*\\\\AppData\\\\*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Scheduled task invokes PowerShell**:

```text
event.provider: "Microsoft-Windows-Security-Auditing" AND (event.code: "4698") AND (winlog.event_data.TaskContent: *powershell.exe*)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "4698"
    }
  },
  {
    "wildcard": {
      "winlog.event_data.TaskContent": {
        "value": "*powershell.exe*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Service installed from a writable path**:

```text
event.provider: "Service Control Manager" AND (event.code: "7045") AND (winlog.event_data.ImagePath: *\\Users\\Public\\*)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "7045"
    }
  },
  {
    "wildcard": {
      "winlog.event_data.ImagePath": {
        "value": "*\\\\Users\\\\Public\\\\*",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- User-installed collaboration software commonly uses Run keys; check publisher and installation history.
- Administration tasks may run signed PowerShell; compare task author, trigger and registration ticket.
- Some legacy installers use writable directories; confirm the vendor and remediate weak permissions.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

Escalate unapproved persistence, particularly a privileged service running from a shared writable path.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
