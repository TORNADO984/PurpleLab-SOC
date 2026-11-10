# Selected detection coverage

Generated from the fixture catalog. **Available does not mean validated.** Run `docker compose run --rm lab validate` to measure alert execution. The Kibana coverage dashboard reports observed alerts and run-scoped outcomes, not all ATT&CK techniques.

| Detection | ATT&CK | Scenario | Event ID | Synthetic fixture | Native rule |
|---|---|---|---|---|---|
| PowerShell encoded command | T1059.001 | [execution](../scenarios/execution.md) | 1 | Available | Available |
| PowerShell web download | T1059.001 | [execution](../scenarios/execution.md) | 1 | Available | Available |
| Unusual LSASS process access | T1003.001 | [credential-access](../scenarios/credential-access.md) | 10 | Available | Available |
| SAM registry hive export | T1003.002 | [credential-access](../scenarios/credential-access.md) | 1 | Available | Available |
| Run key points into a user profile | T1547.001 | [persistence](../scenarios/persistence.md) | 13 | Available | Available |
| Scheduled task invokes PowerShell | T1053.005 | [persistence](../scenarios/persistence.md) | 4698 | Available | Available |
| Service installed from a writable path | T1543.003 | [persistence](../scenarios/persistence.md) | 7045 | Available | Available |
| Interactive user discovery | T1033 | [discovery](../scenarios/discovery.md) | 1 | Available | Available |
| Local account enumeration | T1087.001 | [discovery](../scenarios/discovery.md) | 1 | Available | Available |
| System information discovery | T1082 | [discovery](../scenarios/discovery.md) | 1 | Available | Available |
| Network host enumeration | T1018 | [discovery](../scenarios/discovery.md) | 1 | Available | Available |
| SMB connection from a script interpreter | T1021.002 | [lateral-movement](../scenarios/lateral-movement.md) | 3 | Available | Available |
| Remote interactive logon | T1021.001 | [lateral-movement](../scenarios/lateral-movement.md) | 4624 | Available | Available |
| Command shell spawned by WMI | T1047 | [lateral-movement](../scenarios/lateral-movement.md) | 1 | Available | Available |
| Windows Security log cleared | T1070.001 | [defense-evasion](../scenarios/defense-evasion.md) | 1102 | Available | Available |
| Audit policy disable command | T1562.002 | [defense-evasion](../scenarios/defense-evasion.md) | 1 | Available | Available |
| DNS query for the lab beacon domain | T1071.004 | [command-and-control](../scenarios/command-and-control.md) | 22 | Available | Available |
| Script interpreter connection to TCP 4444 | T1071.001 | [command-and-control](../scenarios/command-and-control.md) | 3 | Available | Available |
| Archive creation in a public directory | T1560.001 | [collection](../scenarios/collection.md) | 1 | Available | Available |
| Archive file created in a public directory | T1074.001 | [collection](../scenarios/collection.md) | 11 | Available | Available |

## Limitations

Rules use observable event fields, never fixture IDs, expected-match labels, or scenario names. Each behavior has one positive and one benign near miss. Discovery and RDP rules are intentionally broad teaching signals. Lab DNS is an explicit .test indicator. Port 4444 does not prove application protocol. Real endpoint collection and adversary emulation require separate validation.
