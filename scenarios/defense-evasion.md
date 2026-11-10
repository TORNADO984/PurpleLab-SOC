# Assess lost Windows audit visibility

A Security log clear and an audit policy disable command are observed. Practice establishing the time window where evidence may be missing.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1070.001, T1562.002. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario defense-evasion
docker compose run --rm lab validate --scenario defense-evasion
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **Windows Security log cleared** (`16c4ef5f-9ebe-5670-9641-262a13deef91`, T1070.001): Clearing the Security log destroys local evidence; central copies may still exist.
- **Audit policy disable command** (`c06f134c-ce0d-5007-b73e-ae03b602a64a`, T1562.002): Disabling auditing can hide later actions. This fixture never changes host policy.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Record the 1102 event time and SubjectUserName from the centralized copy before changing any host state.
2. Inspect the auditpol command and identify success/failure auditing changes. The fixture is text only and performs no policy change.
3. Compare the actor and timing against a documented maintenance or policy rollout ticket.
4. Check whether subsequent Security events continue to arrive. Distinguish a disabled source from a broken shipper or clock skew.
5. For a real case, request policy-change events, collector health, authentication records and independent EDR telemetry covering the missing interval.
6. Escalate unexplained evidence destruction. Restore collection only under the incident lead's approval and preserve the before/after policy state.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "defense-evasion" AND host.name: "win-lab-01"
(event.code: "1102" OR process.name: "auditpol.exe") AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **Windows Security log cleared**:

```text
event.provider: "Microsoft-Windows-Security-Auditing" AND (event.code: "1102")
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "1102"
    }
  }
]
```

KQL equivalent for investigation of **Audit policy disable command**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\auditpol.exe) AND (process.command_line: */set* AND process.command_line: *disable*)
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
        "value": "*\\\\auditpol.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*/set*",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*disable*",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- A documented maintenance reset may clear a lab log; production resets require explicit approval.
- Policy rollout can adjust auditing; verify the intended policy and subsequent telemetry availability.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

Unapproved log clearing or auditing disablement is high priority; the absence of later logs is a collection gap, not evidence of inactivity.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
