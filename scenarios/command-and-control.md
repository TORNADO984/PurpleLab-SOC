# Triage lab DNS and unusual egress

A simulator queries a reserved .test domain and PowerShell connects to TCP 4444. Understand the limits of indicator and port-based detections.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1071.001, T1071.004. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario command-and-control
docker compose run --rm lab validate --scenario command-and-control
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **DNS query for the lab beacon domain** (`a1b4ebbb-cf3b-502d-ad08-9760242b2794`, T1071.004): A lab-only DNS indicator exercises domain matching; it does not detect arbitrary DNS tunneling.
- **Script interpreter connection to TCP 4444** (`8f6149b6-c26a-5fdb-9c96-8e0b22059ef7`, T1071.001): A lab HTTP-like connection on an unusual port exercises egress triage. Port alone cannot establish protocol.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Extract dns.question.name, process.executable and host. Confirm the .purplelab.test suffix is an intentional lab indicator.
2. Inspect the second event's destination IP, port and process. The 198.51.100.0/24 address range is documentation-only.
3. Search nearby DNS and connection events for the same process entity. Do not infer a DNS-to-IP link when one is absent.
4. Request proxy or packet metadata to verify protocol in a real case. TCP 4444 alone cannot prove HTTP, a reverse shell or command and control.
5. Check approved development services and simulation schedules before classifying the behavior.
6. Write a validation result plus a tuning proposal: replace lab indicators with reviewed intelligence and combine network context with process ancestry.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "command-and-control" AND host.name: "win-lab-01"
(event.code: ("22" OR "3")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **DNS query for the lab beacon domain**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "22") AND (dns.question.name: *.purplelab.test)
```

The installed native rule uses a provider KQL clause plus these filter conditions:

```json
[
  {
    "term": {
      "event.code": "22"
    }
  },
  {
    "wildcard": {
      "dns.question.name": {
        "value": "*.purplelab.test",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Script interpreter connection to TCP 4444**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "3") AND (process.executable: *\\powershell.exe) AND (destination.port: "4444")
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
      "destination.port": 4444
    }
  }
]
```

## Known false positives and tuning

- All .purplelab.test queries are training indicators. Replace this indicator for a real environment.
- Developers may run test services on this port; confirm protocol with proxy or packet evidence.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

These fixtures validate field mapping and rule execution. They do not establish general DNS tunneling or protocol detection coverage.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
