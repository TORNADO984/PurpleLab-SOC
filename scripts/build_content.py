"""Rebuild checked-in fixtures, Sigma/native rules and Kibana objects deterministically.

The converter deliberately supports only this repository's documented Sigma subset.
Install the dev extra to run it; runtime containers require only Python's stdlib.
"""

import json
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from purplelab.events import make_event  # noqa: E402

SYS = "Microsoft-Windows-Sysmon"
SEC = "Microsoft-Windows-Security-Auditing"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"


def case(slug, title, technique, technique_name, tactic, scenario, code, fields, selection, negative,
         fp, reason, category="process", provider=SYS, severity="medium"):
    positive = {"event.code": str(code), "event.provider": provider, **fields}
    return dict(id=slug, title=title, technique=technique, technique_name=technique_name, tactic=tactic,
                scenario=scenario, category=category, severity=severity,
                positive=positive, negative={**positive, **negative},
                selection={"EventID": code, **selection}, false_positive=fp, rationale=reason,
                uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/TORNADO984/PurpleLab-SOC/" + slug)))


CASES = [
    case("encoded-powershell", "PowerShell encoded command", "T1059.001", "PowerShell", "execution", "execution", 1,
         {"process.executable": PS, "process.command_line": "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABsAGEAYgA="},
         {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-EncodedCommand"},
         {"process.command_line": "powershell.exe -NoProfile -Command Get-Date"},
         "Management agents may encode trusted scripts; validate the decoded content and approved deployment.",
         "Encoded script execution can conceal intent; encoding alone is not proof of maliciousness."),
    case("powershell-download", "PowerShell web download", "T1059.001", "PowerShell", "execution", "execution", 1,
         {"process.executable": PS, "process.command_line": "powershell.exe Invoke-WebRequest https://updates.purplelab.test/check.txt"},
         {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "Invoke-WebRequest"},
         {"process.command_line": "powershell.exe Get-Process"},
         "Signed deployment scripts can retrieve approved packages; compare the URL to the change ticket.",
         "A web request from PowerShell deserves contextual review; no request is actually made by this fixture."),
    case("lsass-access", "Unusual LSASS process access", "T1003.001", "LSASS Memory", "credential-access", "credential-access", 10,
         {"process.executable": r"C:\Lab\diagnostic.exe", "winlog.event_data.TargetImage": r"C:\Windows\System32\lsass.exe",
          "winlog.event_data.GrantedAccess": "0x1fffff"},
         {"TargetImage|endswith": "\\lsass.exe", "GrantedAccess": ["0x1fffff", "0x1f0fff"]},
         {"winlog.event_data.GrantedAccess": "0x1000"},
         "EDR and approved diagnostic tools may access LSASS; corroborate signature, owner and access mask.",
         "High access masks against LSASS can indicate credential access. This does not prove a dump occurred.", severity="high"),
    case("sam-export", "SAM registry hive export", "T1003.002", "Security Account Manager", "credential-access", "credential-access", 1,
         {"process.executable": r"C:\Windows\System32\reg.exe", "process.command_line": r"reg.exe save HKLM\SAM C:\Lab\sam.hiv"},
         {"Image|endswith": "\\reg.exe", "CommandLine|contains|all": ["save", "HKLM\\SAM"]},
         {"process.command_line": r"reg.exe query HKLM\SOFTWARE"},
         "Authorized forensic acquisition may export hives; require a case number and explicit host approval.",
         "Exporting SAM can expose local password hashes; correlate with SYSTEM hive access.", severity="high"),
    case("run-key", "Run key points into a user profile", "T1547.001", "Registry Run Keys / Startup Folder", "persistence", "persistence", 13,
         {"registry.path": r"HKU\S-1-5-21-1000\Software\Microsoft\Windows\CurrentVersion\Run\LabUpdater",
          "winlog.event_data.Details": r"C:\Users\lab.analyst\AppData\Local\Lab\updater.exe", "process.executable": CMD},
         {"TargetObject|contains": "\\CurrentVersion\\Run\\", "Details|contains": "\\AppData\\"},
         {"registry.path": r"HKCU\Software\PurpleLab\Preferences"},
         "User-installed collaboration software commonly uses Run keys; check publisher and installation history.",
         "User-writable autorun targets can provide persistence.", category="registry"),
    case("scheduled-task", "Scheduled task invokes PowerShell", "T1053.005", "Scheduled Task", "persistence", "persistence", 4698,
         {"winlog.event_data.TaskName": r"\Lab\Inventory", "winlog.event_data.TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>"},
         {"TaskContent|contains": "powershell.exe"},
         {"winlog.event_data.TaskContent": "<Task><Actions><Exec><Command>notepad.exe</Command></Exec></Actions></Task>"},
         "Administration tasks may run signed PowerShell; compare task author, trigger and registration ticket.",
         "PowerShell scheduled execution warrants examination of the complete task XML.",
         category="configuration", provider=SEC),
    case("service-install", "Service installed from a writable path", "T1543.003", "Windows Service", "persistence", "persistence", 7045,
         {"winlog.event_data.ServiceName": "LabUpdate", "winlog.event_data.ImagePath": r"C:\Users\Public\Lab\service.exe"},
         {"ImagePath|contains": "\\Users\\Public\\"},
         {"winlog.event_data.ImagePath": r"C:\Program Files\ApprovedVendor\service.exe"},
         "Some legacy installers use writable directories; confirm the vendor and remediate weak permissions.",
         "A service executable in a shared writable directory creates a persistence opportunity.",
         category="configuration", provider="Service Control Manager", severity="high"),
    case("user-discovery", "Interactive user discovery", "T1033", "System Owner/User Discovery", "discovery", "discovery", 1,
         {"process.executable": r"C:\Windows\System32\whoami.exe", "process.command_line": "whoami.exe /all"},
         {"Image|endswith": "\\whoami.exe", "CommandLine|contains": "/all"},
         {"process.executable": r"C:\Windows\System32\hostname.exe", "process.command_line": "hostname.exe"},
         "Helpdesk scripts often collect identity and group membership; this is a low-confidence behavioral signal.",
         "Full identity and privilege enumeration is useful after initial access.", severity="low"),
    case("account-discovery", "Local account enumeration", "T1087.001", "Local Account", "discovery", "discovery", 1,
         {"process.executable": r"C:\Windows\System32\net.exe", "process.command_line": "net.exe user"},
         {"Image|endswith": ["\\net.exe", "\\net1.exe"], "CommandLine|contains": " user"},
         {"process.command_line": "net.exe help"},
         "Inventory and support tasks enumerate users; correlate with the operator's change window.",
         "Account enumeration may precede credential attacks.", severity="low"),
    case("system-discovery", "System information discovery", "T1082", "System Information Discovery", "discovery", "discovery", 1,
         {"process.executable": r"C:\Windows\System32\systeminfo.exe", "process.command_line": "systeminfo.exe"},
         {"Image|endswith": "\\systeminfo.exe"},
         {"process.executable": r"C:\Windows\System32\notepad.exe", "process.command_line": "notepad.exe"},
         "Asset inventory routinely collects operating system information; inspect parent process and surrounding events.",
         "Host reconnaissance is relevant when chained with other unusual behavior.", severity="low"),
    case("network-discovery", "Network host enumeration", "T1018", "Remote System Discovery", "discovery", "discovery", 1,
         {"process.executable": r"C:\Windows\System32\net.exe", "process.command_line": "net.exe view /domain"},
         {"Image|endswith": ["\\net.exe", "\\net1.exe"], "CommandLine|contains": " view"},
         {"process.command_line": "net.exe help"},
         "Administrators use net view to diagnose browsing; compare source host and account to normal support activity.",
         "Remote host discovery can reveal lateral movement targets.", severity="low"),
    case("smb-connection", "SMB connection from a script interpreter", "T1021.002", "SMB/Windows Admin Shares", "lateral-movement", "lateral-movement", 3,
         {"process.executable": PS, "destination.ip": "192.0.2.20", "destination.port": 445, "network.transport": "tcp"},
         {"Image|endswith": "\\powershell.exe", "DestinationPort": 445},
         {"destination.port": 443},
         "Approved automation can access SMB shares; verify destination ownership and authentication events.",
         "An interpreter connecting to SMB is a contextual signal, not proof of remote execution.", category="network"),
    case("rdp-logon", "Remote interactive logon", "T1021.001", "Remote Desktop Protocol", "lateral-movement", "lateral-movement", 4624,
         {"winlog.event_data.LogonType": "10", "source.ip": "192.0.2.30", "event.outcome": "success", "winlog.event_data.TargetUserName": "lab.operator"},
         {"LogonType": "10"},
         {"winlog.event_data.LogonType": "2"},
         "RDP is normal for approved administrators; verify source, destination, MFA and session authorization.",
         "Remote interactive logons support lateral movement investigation but are common benign events.", category="authentication", provider=SEC, severity="low"),
    case("wmi-child", "Command shell spawned by WMI", "T1047", "Windows Management Instrumentation", "execution", "lateral-movement", 1,
         {"process.executable": CMD, "process.parent.executable": r"C:\Windows\System32\wbem\WmiPrvSE.exe", "process.command_line": "cmd.exe /c echo purplelab"},
         {"Image|endswith": "\\cmd.exe", "ParentImage|endswith": "\\WmiPrvSE.exe"},
         {"process.parent.executable": r"C:\Windows\explorer.exe"},
         "Enterprise management platforms use WMI; correlate source logon and approved job history.",
         "WMI-spawned command interpreters can indicate remote execution.", severity="high"),
    case("security-log-cleared", "Windows Security log cleared", "T1070.001", "Clear Windows Event Logs", "defense-evasion", "defense-evasion", 1102,
         {"winlog.event_data.SubjectUserName": "lab.operator"}, {"EventID": 1102},
         {"event.code": "1100"},
         "A documented maintenance reset may clear a lab log; production resets require explicit approval.",
         "Clearing the Security log destroys local evidence; central copies may still exist.",
         category="configuration", provider=SEC, severity="high"),
    case("audit-disabled", "Audit policy disable command", "T1562.002", "Disable Windows Event Logging", "defense-evasion", "defense-evasion", 1,
         {"process.executable": r"C:\Windows\System32\auditpol.exe", "process.command_line": "auditpol.exe /set /category:* /success:disable /failure:disable"},
         {"Image|endswith": "\\auditpol.exe", "CommandLine|contains|all": ["/set", "disable"]},
         {"process.command_line": "auditpol.exe /get /category:*"},
         "Policy rollout can adjust auditing; verify the intended policy and subsequent telemetry availability.",
         "Disabling auditing can hide later actions. This fixture never changes host policy.", severity="high"),
    case("lab-dns-beacon", "DNS query for the lab beacon domain", "T1071.004", "DNS", "command-and-control", "command-and-control", 22,
         {"process.executable": r"C:\Lab\beacon-simulator.exe", "dns.question.name": "beacon.purplelab.test"},
         {"QueryName|endswith": ".purplelab.test"},
         {"dns.question.name": "www.example.com"},
         "All .purplelab.test queries are training indicators. Replace this indicator for a real environment.",
         "A lab-only DNS indicator exercises domain matching; it does not detect arbitrary DNS tunneling.", category="network"),
    case("unusual-egress", "Script interpreter connection to TCP 4444", "T1071.001", "Web Protocols", "command-and-control", "command-and-control", 3,
         {"process.executable": PS, "destination.ip": "198.51.100.10", "destination.port": 4444, "network.transport": "tcp"},
         {"Image|endswith": "\\powershell.exe", "DestinationPort": 4444},
         {"destination.port": 443},
         "Developers may run test services on this port; confirm protocol with proxy or packet evidence.",
         "A lab HTTP-like connection on an unusual port exercises egress triage. Port alone cannot establish protocol.", category="network"),
    case("archive-staging", "Archive creation in a public directory", "T1560.001", "Archive via Utility", "collection", "collection", 1,
         {"process.executable": r"C:\Program Files\7-Zip\7z.exe", "process.command_line": r"7z.exe a C:\Users\Public\Lab\bundle.zip C:\Lab\Reports\*"},
         {"Image|endswith": "\\7z.exe", "CommandLine|contains|all": [" a ", "\\Users\\Public\\"]},
         {"process.command_line": "7z.exe l C:\\Lab\\approved.zip"},
         "Support bundles and backups are often archived; verify source data, destination and authorized recipient.",
         "An archive in a shared staging directory can precede transfer; it is not proof of exfiltration."),
    case("staged-archive", "Archive file created in a public directory", "T1074.001", "Local Data Staging", "collection", "collection", 11,
         {"process.executable": r"C:\Program Files\7-Zip\7z.exe", "file.path": r"C:\Users\Public\Lab\bundle.zip"},
         {"TargetFilename|contains": "\\Users\\Public\\", "TargetFilename|endswith": ".zip"},
         {"file.path": r"C:\Users\lab.analyst\Documents\approved.zip"},
         "Approved support collections can use public folders; review permissions and retention.",
         "File creation corroborates archive staging but not any subsequent transfer.", category="file"),
]

FIELD_MAP = {
    "EventID": "event.code", "Image": "process.executable", "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable", "DestinationPort": "destination.port",
    "TargetFilename": "file.path", "TargetObject": "registry.path", "QueryName": "dns.question.name",
}
TACTICS = {
    "execution": ("TA0002", "Execution"), "persistence": ("TA0003", "Persistence"),
    "credential-access": ("TA0006", "Credential Access"), "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"), "defense-evasion": ("TA0005", "Defense Evasion"),
    "command-and-control": ("TA0011", "Command and Control"), "collection": ("TA0009", "Collection"),
}
PARENTS = {
    "T1059": "Command and Scripting Interpreter", "T1003": "OS Credential Dumping",
    "T1547": "Boot or Logon Autostart Execution", "T1053": "Scheduled Task/Job",
    "T1543": "Create or Modify System Process", "T1087": "Account Discovery",
    "T1021": "Remote Services", "T1070": "Indicator Removal", "T1562": "Impair Defenses",
    "T1071": "Application Layer Protocol", "T1560": "Archive Collected Data", "T1074": "Data Staged",
}


def kql_value(value, modifier):
    if modifier is None:
        return json.dumps(str(value))
    escaped = str(value)
    for char in ('\\', '(', ')', ':', '<', '>', '"', '*'):
        escaped = escaped.replace(char, "\\" + char)
    return "*" + escaped + ("*" if modifier == "contains" else "")


def convert(selection, provider):
    parts = [f"event.provider: {json.dumps(provider)}"]
    for key, value in selection.items():
        field, *modifiers = key.split("|")
        if modifiers not in ([], ["contains"], ["endswith"], ["contains", "all"]):
            raise ValueError(f"Unsupported Sigma modifier: {key}")
        field = FIELD_MAP.get(field, "winlog.event_data." + field)
        values = value if isinstance(value, list) else [value]
        joiner = " AND " if "all" in modifiers else " OR "
        parts.append("(" + joiner.join(f"{field}: {kql_value(v, modifiers[0] if modifiers else None)}" for v in values) + ")")
    return " AND ".join(parts)


def threat(case):
    identifier = case["technique"]
    parent = identifier.split(".")[0]
    technique = {"id": parent, "name": PARENTS.get(parent, case["technique_name"]),
                 "reference": f"https://attack.mitre.org/techniques/{parent}/"}
    if "." in identifier:
        technique["subtechnique"] = [{"id": identifier, "name": case["technique_name"],
                                     "reference": f"https://attack.mitre.org/techniques/{identifier.replace('.', '/')}/"}]
    tactic_id, tactic_name = TACTICS[case["tactic"]]
    return [{"framework": "MITRE ATT&CK", "tactic": {"id": tactic_id, "name": tactic_name,
             "reference": f"https://attack.mitre.org/tactics/{tactic_id}/"}, "technique": [technique]}]


def elastic_filters(selection):
    filters = []
    for key, value in selection.items():
        raw, *modifiers = key.split("|")
        field = FIELD_MAP.get(raw, "winlog.event_data." + raw)
        values = value if isinstance(value, list) else [value]
        clauses = []
        for v in values:
            if modifiers:
                pattern = str(v).replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
                pattern = "*" + pattern + ("*" if "contains" in modifiers else "")
                clauses.append({"wildcard": {field: {"value": pattern, "case_insensitive": True}}})
            else:
                clauses.append({"term": {field: str(v) if field != "destination.port" else int(v)}})
        if len(clauses) == 1:
            filters.extend(clauses)
        elif "all" in modifiers:
            filters.extend(clauses)
        else:
            filters.append({"bool": {"should": clauses, "minimum_should_match": 1}})
    return filters


def write(path, content):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="\n")


def build_rules():
    native = []
    for item in CASES:
        item["query"] = convert(item["selection"], item["positive"]["event.provider"])
        provider = item["positive"]["event.provider"]
        service = "sysmon" if provider == SYS else "security" if provider == SEC else "system"
        sigma = {
            "title": item["title"], "id": item["uuid"], "status": "experimental",
            "description": item["rationale"], "author": "PurpleLab-SOC contributors",
            "date": "2026-11-10", "license": "MIT", "references": [
                "https://attack.mitre.org/techniques/" + item["technique"].replace(".", "/") + "/"],
            "tags": ["attack." + item["tactic"].replace("-", "_"), "attack." + item["technique"].lower()],
            "logsource": {"product": "windows", "service": service},
            "detection": {"selection": item["selection"], "condition": "selection"},
            "falsepositives": [item["false_positive"]], "level": item["severity"],
        }
        write("rules/sigma/" + item["id"] + ".yml", yaml.safe_dump(sigma, sort_keys=False, allow_unicode=True))
        rule = {
            "rule_id": item["uuid"], "name": "PurpleLab | " + item["title"],
            "description": item["rationale"], "author": ["PurpleLab-SOC"], "license": "MIT",
            "type": "query", "language": "kuery", "index": ["purplelab-events-*"],
            "query": "event.provider: " + json.dumps(provider),
            "filters": elastic_filters(item["selection"]),
            "interval": "1m", "from": "now-6m", "to": "now",
            "severity": item["severity"], "risk_score": {"low": 21, "medium": 47, "high": 73}[item["severity"]],
            "enabled": True, "max_signals": 1000, "version": 1,
            "false_positives": [item["false_positive"]], "threat": threat(item),
            "tags": ["PurpleLab", "synthetic-compatible", item["technique"], item["scenario"]],
            "references": sigma["references"],
            "note": "Follow scenarios/" + item["scenario"] + ".md. Validate host, parent process and authorization before classifying.",
        }
        item["native_filters"] = rule["filters"]
        native.append(rule)
    write("rules/catalog.json", json.dumps(CASES, indent=2) + "\n")
    write("rules/elastic/rules.ndjson", "".join(json.dumps(rule) + "\n" for rule in native))
    for polarity in ("positive", "negative"):
        docs = [make_event(item, "fixture-reference", polarity == "negative", "2026-11-10T12:00:00+00:00") for item in CASES]
        # Reproducible fixture IDs; live runs always use fresh UUIDs and current timestamps.
        for item, doc in zip(CASES, docs):
            doc["event"]["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, polarity + item["id"]))
            doc["winlog"]["record_id"] = CASES.index(item) + 1
            if "process" in doc:
                doc["process"]["entity_id"] = "{" + doc["event"]["id"] + "}"
                doc["winlog"].setdefault("event_data", {})["ProcessGuid"] = doc["process"]["entity_id"]
        write("generators/fixtures/" + polarity + ".ndjson", "".join(json.dumps(doc) + "\n" for doc in docs))


SCENARIOS = {
    "execution": {
        "title": "Investigate suspicious PowerShell execution", "story": "A workstation produces encoded PowerShell and a web retrieval command. Determine whether they belong to an authorized deployment or require escalation.",
        "steps": ["Open the encoded-command alert, record the UTC timestamp, host, user and full command line. Do not execute it.",
                  "Decode the Base64 argument as text in an offline analysis tool (UTF-16LE). This fixture decodes to Write-Output lab. Explain why encoding is not itself malicious.",
                  "Pivot on host.name and process.entity_id to inspect process ancestry. Record missing parent or signature fields as collection gaps.",
                  "Find the companion Invoke-WebRequest event and extract the URL. The .test destination is inert training data; do not browse to a suspect URL.",
                  "Compare the timeline with approved deployment activity. For a real incident, request proxy, DNS, script-block (4104) and file creation evidence.",
                  "Classify the training case as a validated detection. Document what additional evidence would justify real containment."],
        "pivot": 'process.executable: *powershell.exe',
        "decision": "Escalate real unexpected encoded script execution with an untrusted parent or destination; document approved automation with its ticket."},
    "credential-access": {
        "title": "Triage credential access indicators", "story": "A diagnostic process requests extensive LSASS access while reg.exe exports the SAM hive. Determine whether this is approved forensic collection.",
        "steps": ["Review Sysmon event 10 and copy SourceImage/TargetImage (or mapped process.executable) and GrantedAccess into the case record.",
                  "Confirm the target is lsass.exe and the mask is 0x1fffff. A handle request alone does not establish that credentials were extracted.",
                  "Search the same host for reg.exe and SAM export. Record destination paths without opening any potentially sensitive output.",
                  "Check the actor's authorization, process signing evidence and forensic collection ticket. The fixture omits signing evidence deliberately.",
                  "Request process tree, file creation and SYSTEM hive access evidence for a real case; list these as unknown if not available.",
                  "For a confirmed unauthorized real action, escalate to the incident lead for isolation and credential rotation under the approved response procedure."],
        "pivot": 'event.code: ("10" OR "1")',
        "decision": "High severity if unapproved access is corroborated; do not claim that password dumping succeeded from these events alone."},
    "persistence": {
        "title": "Review three persistence mechanisms", "story": "An endpoint adds an AppData Run key, creates a PowerShell task, and installs a service under a shared writable directory.",
        "steps": ["Identify each of the three alerts and order them by @timestamp. Record user and host context independently for each.",
                  "Read registry.path and Details. Determine which account owns the Run key and whether its executable directory is writable.",
                  "Inspect TaskName and TaskContent as text. Extract the command; request complete trigger, principal and author fields in a real investigation.",
                  "Inspect service name and ImagePath. Compare the binary path to authorized software inventory and expected file permissions.",
                  "Search for execution of the referenced paths after registration. The synthetic scenario demonstrates registration only, so absence of execution does not prove removal.",
                  "Document an approval or escalation decision for each mechanism. In a real response, preserve configuration and binary evidence before approved removal."],
        "pivot": 'event.code: ("13" OR "4698" OR "7045")',
        "decision": "Escalate unapproved persistence, particularly a privileged service running from a shared writable path."},
    "discovery": {
        "title": "Build a reconnaissance timeline", "story": "A lab account runs identity, account, system and network enumeration commands. Practice combining weak signals without treating routine administration as an incident.",
        "steps": ["Collect the four discovery alerts and record the exact command lines and process names.",
                  "Order the events by UTC timestamp. The synthetic fixtures share a host/user, but do not prove a common parent process.",
                  "Explain what each command reveals: identity privileges, local accounts, OS details and reachable systems.",
                  "Compare the user and schedule to helpdesk or asset-management jobs. Request the originating logon and parent process tree.",
                  "Pivot to execution, credential access and remote logon evidence around the same time. Record whether the broader chain exists.",
                  "Write a low-confidence disposition when corroboration is absent; propose narrow exclusions using approved process ancestry rather than blanket tool exclusions."],
        "pivot": 'process.name: ("whoami.exe" OR "net.exe" OR "systeminfo.exe")',
        "decision": "Escalate only when context or a broader chain supports unauthorized reconnaissance."},
    "lateral-movement": {
        "title": "Investigate remote access indicators", "story": "A PowerShell SMB connection, an RDP logon and a WMI-spawned shell appear. Distinguish observed remote activity from an inferred attack path.",
        "steps": ["Record source and destination addresses for the network and authentication events. These are documentation-only IP ranges.",
                  "Inspect the Sysmon connection: destination port 445 and PowerShell image. Request share name and SMB server logs for a real case.",
                  "Read the 4624 LogonType 10 event and target user. Compare source IP and time to authorized jump-host access.",
                  "Inspect the WmiPrvSE.exe parent of cmd.exe. Request associated network logon events and management platform job records.",
                  "Avoid assuming all three events form one session: this fixture intentionally lacks a shared logon ID. State the correlation gap.",
                  "Document permitted administration or escalate unexpected remote access. Preserve both source and destination evidence before approved isolation."],
        "pivot": 'event.code: ("3" OR "4624" OR "1")',
        "decision": "An unexpected account/source combined with WMI execution merits escalation; an RDP event alone is informational."},
    "defense-evasion": {
        "title": "Assess lost Windows audit visibility", "story": "A Security log clear and an audit policy disable command are observed. Practice establishing the time window where evidence may be missing.",
        "steps": ["Record the 1102 event time and SubjectUserName from the centralized copy before changing any host state.",
                  "Inspect the auditpol command and identify success/failure auditing changes. The fixture is text only and performs no policy change.",
                  "Compare the actor and timing against a documented maintenance or policy rollout ticket.",
                  "Check whether subsequent Security events continue to arrive. Distinguish a disabled source from a broken shipper or clock skew.",
                  "For a real case, request policy-change events, collector health, authentication records and independent EDR telemetry covering the missing interval.",
                  "Escalate unexplained evidence destruction. Restore collection only under the incident lead's approval and preserve the before/after policy state."],
        "pivot": 'event.code: "1102" OR process.name: "auditpol.exe"',
        "decision": "Unapproved log clearing or auditing disablement is high priority; the absence of later logs is a collection gap, not evidence of inactivity."},
    "command-and-control": {
        "title": "Triage lab DNS and unusual egress", "story": "A simulator queries a reserved .test domain and PowerShell connects to TCP 4444. Understand the limits of indicator and port-based detections.",
        "steps": ["Extract dns.question.name, process.executable and host. Confirm the .purplelab.test suffix is an intentional lab indicator.",
                  "Inspect the second event's destination IP, port and process. The 198.51.100.0/24 address range is documentation-only.",
                  "Search nearby DNS and connection events for the same process entity. Do not infer a DNS-to-IP link when one is absent.",
                  "Request proxy or packet metadata to verify protocol in a real case. TCP 4444 alone cannot prove HTTP, a reverse shell or command and control.",
                  "Check approved development services and simulation schedules before classifying the behavior.",
                  "Write a validation result plus a tuning proposal: replace lab indicators with reviewed intelligence and combine network context with process ancestry."],
        "pivot": 'event.code: ("22" OR "3")',
        "decision": "These fixtures validate field mapping and rule execution. They do not establish general DNS tunneling or protocol detection coverage."},
    "collection": {
        "title": "Trace local archive staging", "story": "7-Zip creates an archive under Users\\Public. Correlate process and file evidence while keeping collection separate from exfiltration.",
        "steps": ["Inspect the 7z.exe command and identify source glob and archive output path. Do not open unknown archives.",
                  "Locate the Sysmon file creation event and compare file.path with the command's output path.",
                  "Record host/user/time and explain that a common path supports correlation but is weaker than a shared process entity.",
                  "Check approved support bundle or backup jobs, data classification and directory permissions.",
                  "Search for subsequent connections or file transfers using the same process/host. This scenario contains no transfer event, so exfiltration remains unproven.",
                  "Document the archive as staged data and request approved metadata/hash collection in a real incident. Avoid placing sensitive contents in the case ticket."],
        "pivot": 'event.code: ("1" OR "11")',
        "decision": "Escalate unapproved collection of sensitive data; do not label the case exfiltration without transfer evidence."},
}


def build_scenarios():
    for slug, scenario in SCENARIOS.items():
        cases = [c for c in CASES if c["scenario"] == slug]
        data = {"id": slug, "name": scenario["title"], "description": scenario["story"],
                "techniques": sorted({c["technique"] for c in cases}), "authorized_use_only": True,
                "generate": f"docker compose run --rm lab generate --scenario {slug}",
                "validate": f"docker compose run --rm lab validate --scenario {slug}",
                "expected_rules": [c["uuid"] for c in cases], "playbook": scenario["steps"],
                "false_positives": [c["false_positive"] for c in cases],
                "queries": [f'purplelab.scenario: "{slug}"', scenario["pivot"]],
                "disposition": scenario["decision"]}
        write(f"scenarios/{slug}.yml", yaml.safe_dump(data, sort_keys=False))
        text = f"# {scenario['title']}\n\n{scenario['story']}\n\n"
        text += "**Authorized use only.** Synthetic commands are inert event strings. Never copy fixture commands into a host shell.\n\n"
        text += "## Learning objectives and prerequisites\n\n"
        text += "Practice evidence collection, correlation, false-positive review, and a justified disposition. Budget 25–40 minutes. Start the lab, wait for successful provisioning, and sign in as `soc_analyst`. Use UTC and a last-15-minutes time window.\n\n"
        text += "ATT&CK: " + ", ".join(data["techniques"]) + ". These are selected observable behaviors, not complete technique coverage.\n\n"
        text += "## Generate and validate\n\n```sh\n" + data["generate"] + "\n" + data["validate"] + "\n```\n\n"
        text += "Generation prints a run ID. In Discover, select **PurpleLab events** and filter `purplelab.run_id: \"<RUN_ID>\"`. In Security alerts, filter `tags: \"purplelab-run-<RUN_ID>\"`. Validation creates its own positive and negative runs and polls real Elastic alerts for up to five minutes.\n\n"
        text += "## Expected detections and true-positive evidence\n\n"
        for c in cases:
            text += f"- **{c['title']}** (`{c['uuid']}`, {c['technique']}): {c['rationale']}\n"
        text += "\nPositive fixtures should trigger every listed rule. Negative fixtures should trigger none of the PurpleLab rules. A synthetic true positive means rule logic matched the intended observation; it does not establish compromise.\n\n"
        text += "## Investigation playbook\n\n" + "\n".join(f"{i}. {step}" for i, step in enumerate(scenario["steps"], 1)) + "\n\n"
        text += "## Evidence queries (KQL)\n\n```text\npurplelab.run_id: \"<RUN_ID>\"\n"
        text += f'purplelab.scenario: "{slug}" AND host.name: "win-lab-01"\n({scenario["pivot"]}) AND host.name: "win-lab-01"\n```\n\n'
        text += "Apply the run-ID filter to each query when isolating a test. In Security → Alerts use:\n\n```text\n"
        text += 'kibana.alert.rule.tags: "PurpleLab" AND tags: "purplelab-run-<RUN_ID>"\n```\n\n'
        for c in cases:
            text += f"KQL equivalent for investigation of **{c['title']}**:\n\n```text\n{c['query']}\n```\n\n"
            text += "The installed native rule uses a provider KQL clause plus these filter conditions:\n\n```json\n"
            text += json.dumps(c["native_filters"], indent=2) + "\n```\n\n"
        text += "## Known false positives and tuning\n\n" + "\n".join(f"- {c['false_positive']}" for c in cases) + "\n\n"
        text += "The checked-in `generators/fixtures/negative.ndjson` contains benign near-miss controls, not exhaustive real-world false positives. Avoid broad exclusions that hide the entire technique.\n\n"
        text += "## Case deliverable and decision\n\n"
        text += "Record run ID, rule IDs, event IDs, UTC timeline, host/user, observed facts, missing evidence, authorization check, confidence, and next owner. Save searches or sanitized JSON; never include credentials.\n\n"
        text += scenario["decision"] + "\n\n## Cleanup\n\nStop containers with `docker compose down` to retain evidence. `python scripts/cleanup.py --purge` destroys this lab's data and credentials after an explicit local confirmation.\n"
        write(f"scenarios/{slug}.md", text)


def source(view, query=""):
    return {"query": {"language": "kuery", "query": query}, "filter": [], "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"}


def build_dashboards():
    objects = []
    for identifier, pattern, title in (("purplelab-events", "purplelab-events-*", "PurpleLab events"),
                                       ("purplelab-alerts", ".alerts-security.alerts-default", "PurpleLab alerts"),
                                       ("purplelab-validation", "purplelab-validation", "PurpleLab validation")):
        objects.append({"type": "index-pattern", "id": identifier,
                        "attributes": {"title": pattern, "name": title, "timeFieldName": "@timestamp"}, "references": []})

    def ref(view):
        return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": view}]

    for identifier, title, view, columns in (
        ("purplelab-event-timeline", "Event timeline", "purplelab-events", ["host.name", "event.code", "process.name", "purplelab.scenario", "message"]),
        ("purplelab-alert-list", "Observed detection alerts", "purplelab-alerts", ["kibana.alert.rule.name", "kibana.alert.severity", "host.name", "tags"]),
        ("purplelab-validation-list", "Run-scoped validation evidence", "purplelab-validation", ["rule_id", "technique", "scenario", "status", "run_id"]),
    ):
        objects.append({"type": "search", "id": identifier, "attributes": {
            "title": title, "description": "PurpleLab lab evidence; synthetic results are not enterprise coverage.",
            "columns": columns, "sort": [["@timestamp", "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source(view))}}, "references": ref(view)})

    for identifier, title, view, field in (
        ("purplelab-techniques", "Observed alert rule tags (includes ATT&CK)", "purplelab-alerts", "kibana.alert.rule.tags"),
        ("purplelab-scenarios", "Generated events by scenario", "purplelab-events", "purplelab.scenario"),
        ("purplelab-status", "Validation results by status", "purplelab-validation", "status"),
    ):
        state = {"title": title, "type": "table", "params": {"perPage": 20, "showPartialRows": False,
                 "showMetricsAtAllLevels": False, "showTotal": True, "totalFunc": "sum"},
                 "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                          {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
                           "params": {"field": field, "size": 30, "order": "desc", "orderBy": "1"}}]}
        objects.append({"type": "visualization", "id": identifier,
                        "attributes": {"title": title, "visState": json.dumps(state), "uiStateJSON": "{}",
                                       "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(source(view))}}, "references": ref(view)})
    for identifier, title, panels in (
        ("purplelab-coverage", "PurpleLab • Detection coverage", [("visualization", "purplelab-techniques"), ("visualization", "purplelab-status"), ("search", "purplelab-validation-list")]),
        ("purplelab-timeline", "PurpleLab • Event timeline", [("search", "purplelab-event-timeline"), ("search", "purplelab-alert-list")]),
        ("purplelab-scenario-dashboard", "PurpleLab • Scenario investigation", [("visualization", "purplelab-scenarios"), ("search", "purplelab-event-timeline"), ("search", "purplelab-alert-list")]),
    ):
        panel_json, references = [], []
        for i, (kind, panel_id) in enumerate(panels):
            name = f"panel_{i}"
            panel_json.append({"panelIndex": str(i), "type": kind, "panelRefName": name,
                               "gridData": {"x": 0, "y": i * 15, "w": 48, "h": 15, "i": str(i)},
                               "embeddableConfig": {}})
            references.append({"name": name, "type": kind, "id": panel_id})
        objects.append({"type": "dashboard", "id": identifier, "attributes": {
            "title": title, "description": "Selected synthetic coverage only. Filter run ID; no results means unvalidated, not covered.",
            "panelsJSON": json.dumps(panel_json), "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": False, "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
            "references": references})
    write("dashboards/purplelab.ndjson", "".join(json.dumps(obj) + "\n" for obj in objects))


def build_coverage():
    text = "# Selected detection coverage\n\nGenerated from the fixture catalog. **Available does not mean validated.** Run `docker compose run --rm lab validate` to measure alert execution. The Kibana coverage dashboard reports observed alerts and run-scoped outcomes, not all ATT&CK techniques.\n\n"
    text += "| Detection | ATT&CK | Scenario | Event ID | Synthetic fixture | Native rule |\n|---|---|---|---|---|---|\n"
    for c in CASES:
        text += f"| {c['title']} | {c['technique']} | [{c['scenario']}](../scenarios/{c['scenario']}.md) | {c['positive']['event.code']} | Available | Available |\n"
    text += "\n## Limitations\n\nRules use observable event fields, never fixture IDs, expected-match labels, or scenario names. Each behavior has one positive and one benign near miss. Discovery and RDP rules are intentionally broad teaching signals. Lab DNS is an explicit .test indicator. Port 4444 does not prove application protocol. Real endpoint collection and adversary emulation require separate validation.\n"
    write("docs/coverage.md", text)


def build_pipeline():
    processors = [{'set': {'field': 'event.ingested', 'value': '{{{_ingest.timestamp}}}'}}]
    mapping = {'winlog.event_id': 'event.code', 'winlog.provider_name': 'event.provider',
               **{'winlog.event_data.' + key: value for key, value in FIELD_MAP.items() if key != 'EventID'},
               'winlog.event_data.SourceImage': 'process.executable',
               'winlog.event_data.DestinationIp': 'destination.ip',
               'winlog.event_data.IpAddress': 'source.ip',
               'winlog.event_data.ProcessGuid': 'process.entity_id',
               'winlog.event_data.TargetUserName': 'user.name'}
    for source, target in mapping.items():
        processors.append({'set': {'field': target, 'copy_from': source, 'ignore_empty_value': True, 'override': False}})
    processors.extend([
      {'convert': {'field': 'event.code', 'type': 'string', 'ignore_missing': True}},
      {'convert': {'field': 'destination.port', 'type': 'integer', 'ignore_missing': True}},
      {'set': {'field': 'purplelab.synthetic', 'value': False, 'override': False}},
      {'set': {'field': 'event.kind', 'value': 'event', 'override': False}},
      {'remove': {'field': 'source.ip', 'if': "ctx.source?.ip == '-' || ctx.source?.ip == ''", 'ignore_missing': True}},
      {'remove': {'field': 'destination.ip', 'if': "ctx.destination?.ip == '-' || ctx.destination?.ip == ''", 'ignore_missing': True}}
    ])
    write('configs/elasticsearch/windows-pipeline.json', json.dumps({
        'description': 'Normalize raw Winlogbeat fields and preserve ECS synthetic fixtures',
        'processors': processors}, indent=2) + '\n')


if __name__ == "__main__":
    build_rules()
    build_scenarios()
    build_dashboards()
    build_pipeline()
    build_coverage()
    print(f"Built {len(CASES)} rules, {len(SCENARIOS)} scenarios and three dashboards.")
