# Build a reconnaissance timeline

A lab account runs identity, account, system and network enumeration commands. Practice combining weak signals without treating routine administration as an incident.

**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.

## Learning objectives and prerequisites

Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.

ATT&CK: T1018, T1033, T1082, T1087.001. These are selected observable behaviors, not complete technique coverage.

## Generate and validate

```sh
docker compose run --rm lab generate --scenario discovery
docker compose run --rm lab validate --scenario discovery
```

Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: "<RUN_ID>"`. In Security alerts, filter `tags: "purplelab-run-<RUN_ID>"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.

## Expected detections and true-positive evidence

- **Interactive user discovery** (`1e155ba5-f9ff-5d3d-b5d9-95dae6612564`, T1033): Full identity and privilege enumeration is useful after initial access.
- **Local account enumeration** (`b153aa43-4a8d-54dc-a2f7-3152a53300e1`, T1087.001): Account enumeration may precede credential attacks.
- **System information discovery** (`b175bb3a-dde4-5c39-866c-d8458e3a2ea4`, T1082): Host reconnaissance is relevant when chained with other unusual behavior.
- **Network host enumeration** (`d434ac0c-2ed4-55ef-bb88-8a25e6fbba27`, T1018): Remote host discovery can reveal lateral movement targets.

Positive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.

## Investigation playbook

1. Collect the four discovery alerts and record the exact command lines and process names.
2. Order the events by UTC timestamp. The synthetic fixtures share a host/user, but do not prove a common parent process.
3. Explain what each command reveals: identity privileges, local accounts, OS details and reachable systems.
4. Compare the user and schedule to helpdesk or asset-management jobs. Request the originating logon and parent process tree.
5. Pivot to execution, credential access and remote logon evidence around the same time. Record whether the broader chain exists.
6. Write a low-confidence disposition when corroboration is absent; propose narrow exclusions using approved process ancestry rather than blanket tool exclusions.

## Evidence queries (KQL)

```text
purplelab.run_id: "<RUN_ID>"
purplelab.scenario: "discovery" AND host.name: "win-lab-01"
(process.name: ("whoami.exe" OR "net.exe" OR "systeminfo.exe")) AND host.name: "win-lab-01"
```

Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:

```text
kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"
```

KQL equivalent for investigation of **Interactive user discovery**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\whoami.exe) AND (process.command_line: */all*)
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
        "value": "*\\\\whoami.exe",
        "case_insensitive": true
      }
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "*/all*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Local account enumeration**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\net.exe OR process.executable: *\\net1.exe) AND (process.command_line: * user*)
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
    "bool": {
      "should": [
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\\\net.exe",
              "case_insensitive": true
            }
          }
        },
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\\\net1.exe",
              "case_insensitive": true
            }
          }
        }
      ],
      "minimum_should_match": 1
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "* user*",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **System information discovery**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\systeminfo.exe)
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
        "value": "*\\\\systeminfo.exe",
        "case_insensitive": true
      }
    }
  }
]
```

KQL equivalent for investigation of **Network host enumeration**:

```text
event.provider: "Microsoft-Windows-Sysmon" AND (event.code: "1") AND (process.executable: *\\net.exe OR process.executable: *\\net1.exe) AND (process.command_line: * view*)
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
    "bool": {
      "should": [
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\\\net.exe",
              "case_insensitive": true
            }
          }
        },
        {
          "wildcard": {
            "process.executable": {
              "value": "*\\\\net1.exe",
              "case_insensitive": true
            }
          }
        }
      ],
      "minimum_should_match": 1
    }
  },
  {
    "wildcard": {
      "process.command_line": {
        "value": "* view*",
        "case_insensitive": true
      }
    }
  }
]
```

## Known false positives and tuning

- Helpdesk scripts often collect identity and group membership; this is a low-confidence behavioral signal.
- Inventory and support tasks enumerate users; correlate with the operator's change window.
- Asset inventory routinely collects operating system information; inspect parent process and surrounding events.
- Administrators use net view to diagnose browsing; compare source host and account to normal support activity.

The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.

## Case deliverable and decision

Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.

Escalate only when context or a broader chain supports unauthorized reconnaissance.

## Cleanup

Stop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.
