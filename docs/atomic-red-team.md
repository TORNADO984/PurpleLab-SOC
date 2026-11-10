# Atomic Red Team compatibility

PurpleLab accepts Windows telemetry produced by Atomic Red Team tests through the documented Sysmon/Winlogbeat pipeline. It does not install Invoke-AtomicRedTeam, download payloads, run an Atomic test automatically, or claim parity with every upstream test.

The repository includes two original harmless Atomic-format tests under `atomics/`: user discovery (`T1033`) and system information discovery (`T1082`). They run standard discovery commands in an authorized Windows VM and map to the shipped detection rules. They create no persistent files and require no cleanup command; revert the VM snapshot after the exercise.

## Procedure

1. Prepare and validate [real VM collection](windows-vm.md). Snapshot the VM.
2. Install Invoke-AtomicRedTeam in that VM following the [upstream documentation](https://www.atomicredteam.io/docs/). Review dependencies before downloading them; never disable security products broadly to make a test work.
3. Copy this repository's `atomics` directory into `C:\PurpleLab-SOC\atomics` in the VM.
4. Inspect the selected test and check prerequisites:

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1033 -PathToAtomicsFolder C:\PurpleLab-SOC\atomics -ShowDetails
Invoke-AtomicTest T1033 -PathToAtomicsFolder C:\PurpleLab-SOC\atomics -CheckPrereqs
```

5. After confirming the command and authorization, run just the bundled user-discovery test **inside the VM**:

```powershell
Invoke-AtomicTest T1033 -PathToAtomicsFolder C:\PurpleLab-SOC\atomics -TestGuids 5bfaf64e-616d-4e36-a3dc-e6b56eea6a10
```

6. Find the real Sysmon process event and corresponding `Interactive user discovery` alert. Record UTC time, host, user, test GUID, rule UUID and event evidence. The automated `lab validate` command generates separate synthetic runs; it does not establish that this real test passed.
7. Stop collection and revert the snapshot. Upstream tests may have dependencies and cleanup commands; review each individually and use their documented cleanup plus snapshot restoration.

## Coverage limits

ATT&CK identifiers describe behavior families, not identical command lines. A Sigma/native rule can miss a different Atomic variant with the same technique ID. Use `docs/coverage.md` and inspect exact native filters when selecting upstream tests. Unsupported fields or variants should be documented as gaps, not counted as successes. Do not run destructive, credential-access, lateral-movement or persistence tests against shared infrastructure merely because a technique appears in this catalog.
