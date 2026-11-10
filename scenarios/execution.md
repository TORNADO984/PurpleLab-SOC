# Investigate suspicious PowerShell execution

A workstation produces encoded PowerShell and a web retrieval command. Determine whether they belong to an authorized deployment or require escalation.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1059.001. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario execution
docker compose run --rm lab validate --scenario execution
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **PowerShell encoded command** (`a8c94457-cf0a-591b-ab17-f7cfc534ef43`, T1059.001): Encoded script execution can conceal intent; encoding alone is not proof of maliciousness.
- **PowerShell web download** (`97eef628-38bf-5d94-9e40-634d871669cc`, T1059.001): A web request from PowerShell deserves contextual review; no request is actually made by this fixture.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Open the encoded-command alert, record the UTC timestamp, host, user and full command line. Do not execute it.
2. Decode the Base64 argument as text in an offline analysis tool (UTF-16LE). This fixture decodes to Write-Output lab. Explain why encoding is not itself malicious.
3. Pivot on host.name and process.entity_id to inspect process ancestry. Record missing parent or signature fields as collection gaps.
4. Find the companion Invoke-WebRequest event and extract the URL. The .test destination is inert training data; do not browse to a suspect URL.
5. Compare the timeline with approved deployment activity. For a real incident, request proxy, DNS, script-block (4104) and file creation evidence.
6. Classify the training case as a validated detection. Document what additional evidence would justify real containment.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "execution" AND host.name: "win-lab-01"
(process.executable: *powershell.exe) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **PowerShell encoded command**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\powershell.exe) AND (process.command_line: *-EncodedCommand*)
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
        "value": "*\\\\powershell.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*-EncodedCommand*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **PowerShell web download**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\powershell.exe) AND (process.command_line: *Invoke-WebRequest*)
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
        "value": "*\\\\powershell.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*Invoke-WebRequest*",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- Management agents may encode trusted scripts; validate the decoded content and approved deployment.
- Signed deployment scripts can retrieve approved packages; compare the URL to the change ticket.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

Escalate real unexpected encoded script execution with an untrusted parent or destination; document approved automation with its ticket.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
