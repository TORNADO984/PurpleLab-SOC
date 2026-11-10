# Investigate remote access indicators

A PowerShell SMB connection, an RDP logon and a WMI-spawned shell appear. Distinguish observed remote activity from an inferred attack path.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1021.001, T1021.002, T1047. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario lateral-movement
docker compose run --rm lab validate --scenario lateral-movement
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **SMB connection from a script interpreter** (`31319808-55f5-5079-9604-e41271523b3a`, T1021.002): An interpreter connecting to SMB is a contextual signal, not proof of remote execution.
- **Remote interactive logon** (`bb77b39b-d1d8-5d06-99c4-d9bf5201b8b7`, T1021.001): Remote interactive logons support lateral movement investigation but are common benign events.
- **Command shell spawned by WMI** (`287bcb26-171d-5446-9c32-7a1ddea96231`, T1047): WMI-spawned command interpreters can indicate remote execution.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Record source and destination addresses for the network and authentication events. These are documentation-only IP ranges.
2. Inspect the Sysmon connection: destination port 445 and PowerShell image. Request share name and SMB server logs for a real case.
3. Read the 4624 LogonType 10 event and target user. Compare source IP and time to authorized jump-host access.
4. Inspect the WmiPrvSE.exe parent of cmd.exe. Request associated network logon events and management platform job records.
5. Avoid assuming all three events form one session: this fixture intentionally lacks a shared logon ID. State the correlation gap.
6. Document permitted administration or escalate unexpected remote access. Preserve both source and destination evidence before approved isolation.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "lateral-movement" AND host.name: "win-lab-01"
(event.code: ("3" OR "4624" OR "1")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **SMB connection from a script interpreter**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "3") AND (process.executable: *\\powershell.exe) AND (destination.port: "445")
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "3"
    }
  },
  {
    "wildcard": {
      "process.executable": {
        "value": "*\\\\powershell.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "term": {
      "destination.port": 445
    }
  }
]
```

KQL equivalent for investigation of **Remote interactive logon**:

```text
event.provider: "Microsoft-Windows-Security-Auditing" AND (event.code: "4624") AND (winlog.event_data.LogonType: "10")
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "4624"
    }
  },
  {
    "term": {
      "winlog.event_data.LogonType": "10"
    }
  }
]
```

KQL equivalent for investigation of **Command shell spawned by WMI**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\cmd.exe) AND (process.parent.executable: *\\WmiPrvSE.exe)
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
        "value": "*\\\\cmd.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.parent.executable": {
        "value": "*\\\\WmiPrvSE.exe",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- Approved automation can access SMB shares; verify destination ownership and authentication events.
- RDP is normal for approved administrators; verify source, destination, MFA and session authorization.
- Enterprise management platforms use WMI; correlate source logon and approved job history.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

An unexpected account/source combined with WMI execution merits escalation; an RDP event alone is informational.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
