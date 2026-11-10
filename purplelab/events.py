"""Generate inert ECS/Sysmon-like documents. Never execute fixture command lines."""
import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def catalog():
    return json.loads((ROOT / "rules/catalog.json").read_text(encoding="utf-8"))


def set_field(document, dotted, value):
    parts = dotted.split(".")
    for part in parts[:-1]:
        document = document.setdefault(part, {})
    document[parts[-1]] = value


def get_field(document, dotted):
    if dotted in document:
        return document[dotted]
    for part in dotted.split("."):
        if not isinstance(document, dict) or part not in document:
            return None
        document = document[part]
    return document


def make_event(case, run_id, negative=False, timestamp=None):
    values = copy.deepcopy(case["negative"] if negative else case["positive"])
    code = str(values.pop("event.code"))
    provider = values.pop("event.provider", "Microsoft-Windows-Sysmon")
    channel = ("Microsoft-Windows-Sysmon/Operational" if "Sysmon" in provider
               else "Security" if "Security" in provider else "System")
    event_id = str(uuid.uuid4())
    doc = {
        "@timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "ecs": {"version": "8.11.0"},
        "event": {"id": event_id, "kind": "event", "category": [case["category"]],
                  "type": ["info"], "code": code, "provider": provider,
                  "dataset": "purplelab.windows", "module": "purplelab"},
        "host": {"name": "win-lab-01", "id": "purplelab-win-lab-01",
                 "os": {"type": "windows", "name": "Windows 11 Enterprise"}},
        "user": {"name": "lab.analyst", "domain": "PURPLELAB"},
        "agent": {"type": "purplelab-synthetic", "version": "1.0.0"},
        "tags": ["purplelab", "purplelab-run-" + run_id,
                 "purplelab-scenario-" + case["scenario"], "attack-" + case["technique"]],
        "winlog": {"event_id": int(code), "channel": channel, "provider_name": provider,
                   "computer_name": "win-lab-01", "record_id": int(uuid.uuid4().int % 1000000)},
        "purplelab": {"run_id": run_id, "scenario": case["scenario"], "case_id": case["id"],
                      "technique": case["technique"], "synthetic": True,
                      "expected_match": not negative},
        "message": f"AUTHORIZED SYNTHETIC FIXTURE: {case['title']}",
    }
    for field, value in values.items():
        set_field(doc, field, value)
    if "process" in doc:
        doc["process"].setdefault("entity_id", "{" + event_id + "}")
        doc["process"].setdefault("pid", 4242)
        if "executable" in doc["process"]:
            doc["process"]["name"] = doc["process"]["executable"].rsplit("\\", 1)[-1]
    raw_mapping = {
        "process.executable": "SourceImage" if code == "10" else "Image",
        "process.command_line": "CommandLine", "process.parent.executable": "ParentImage",
        "process.entity_id": "ProcessGuid", "destination.ip": "DestinationIp",
        "destination.port": "DestinationPort", "file.path": "TargetFilename",
        "registry.path": "TargetObject", "dns.question.name": "QueryName",
    }
    for field, raw in raw_mapping.items():
        value = get_field(doc, field)
        if value is not None:
            set_field(doc, f"winlog.event_data.{raw}", str(value))
    return doc


def generate(scenario="all", negative=False, run_id=None):
    cases = [case for case in catalog() if scenario == "all" or case["scenario"] == scenario]
    if not cases:
        raise ValueError(f"Unknown scenario: {scenario}")
    run_id = run_id or str(uuid.uuid4())
    return run_id, [make_event(case, run_id, negative) for case in cases]
