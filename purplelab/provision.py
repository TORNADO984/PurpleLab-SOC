"""Idempotent first-boot provisioning through supported Elastic APIs."""

import json
import os
import secrets
from pathlib import Path

from .client import ApiError, Client, secret
from .events import ROOT

USERS = ("elastic", "kibana_system", "soc_analyst", "detection_engineer", "event_writer", "beats_writer")


def init_secrets():
    root = Path(os.environ.get("PURPLELAB_STATE", "/state"))
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o750)
    for name in (*USERS, "saved_objects_key", "session_key", "reporting_key"):
        path = root / name
        if not path.exists():
            # Atomic exclusive create avoids replacing credentials on subsequent startup.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
            with os.fdopen(fd, "w") as handle:
                handle.write(secrets.token_hex(32) + "\n")
    print("Generated credentials are stored in the Docker secrets volume; existing values preserved.")
    writer = Path(os.environ.get("PURPLELAB_WRITER_STATE", "/writer"))
    writer.mkdir(parents=True, exist_ok=True)
    writer.chmod(0o750)
    for name in ("event_writer", "beats_writer"):
        destination = writer / name
        destination.write_text((root / name).read_text())
        destination.chmod(0o640)


def setup_security():
    Client().request("POST", "/_security/user/kibana_system/_password", {"password": secret("kibana_system")})
    print("Kibana service credentials configured.")


def import_objects(kibana, path):
    boundary = "PurpleLab" + secrets.token_hex(16)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="lab.ndjson"\r\n'
            'Content-Type: application/ndjson\r\n\r\n').encode() + path.read_bytes()
    body += f"\r\n--{boundary}--\r\n".encode()
    result = kibana.request("POST", "/api/saved_objects/_import?overwrite=true", body,
                            f"multipart/form-data; boundary={boundary}")
    if not result.get("success"):
        raise RuntimeError(f"Dashboard import failed: {result.get('errors')}")
    return result["successCount"]


def provision():
    es, kibana = Client(), Client("kibana")
    es.request("PUT", "/_ilm/policy/purplelab-retention", {
        "policy": {"phases": {"hot": {"actions": {}}, "delete": {"min_age": "7d", "actions": {"delete": {}}}}}
    })
    for kind, path in (("_ingest/pipeline/purplelab-windows", "configs/elasticsearch/windows-pipeline.json"),
                       ("_index_template/purplelab-events", "configs/elasticsearch/events-template.json")):
        es.request("PUT", "/" + kind, json.loads((ROOT / path).read_text()))
    es.request("PUT", "/_security/role/purplelab_writer", {
        "cluster": [], "indices": [{"names": ["purplelab-events-*"],
                                      "privileges": ["create_doc", "auto_configure"]}]})
    es.request("PUT", "/_security/role/purplelab_beats", {
        "cluster": ["monitor"], "indices": [{"names": ["purplelab-events-*"],
                                               "privileges": ["create_doc", "auto_configure"]}]})
    indices = [{"names": ["purplelab-events-*", ".alerts-security.alerts-default"],
                "privileges": ["read", "view_index_metadata"]},
               {"names": ["purplelab-validation"], "privileges": ["read", "view_index_metadata"]}]
    for role, level in (("soc_analyst", "read"), ("detection_engineer", "all")):
        role_indices = json.loads(json.dumps(indices))
        if level == "all":
            role_indices.append({"names": [".alerts-security.alerts-default", ".lists-default", ".items-default"],
                                 "privileges": ["read", "write", "view_index_metadata", "maintenance"]})
        kibana.request("PUT", "/api/security/role/purplelab_" + role, {
            "elasticsearch": {"cluster": ["manage_own_api_key"] if level == "all" else [],
                              "indices": role_indices},
            "kibana": [{"base": [level], "spaces": ["default"]}],
        })
    for username, role in (("soc_analyst", "soc_analyst"), ("detection_engineer", "detection_engineer"),
                           ("event_writer", "writer"), ("beats_writer", "beats")):
        es.request("PUT", "/_security/user/" + username, {
            "password": secret(username), "roles": ["purplelab_" + role],
            "full_name": username.replace("_", " ").title(),
        })
    try:
        es.request("PUT", "/purplelab-validation", {
            "mappings": {"properties": {"@timestamp": {"type": "date"}, "run_id": {"type": "keyword"},
                                        "rule_id": {"type": "keyword"}, "technique": {"type": "keyword"},
                                        "scenario": {"type": "keyword"}, "status": {"type": "keyword"},
                                        "synthetic": {"type": "boolean"}}}})
    except ApiError as exc:
        if exc.status != 400 or "resource_already_exists_exception" not in str(exc):
            raise
    # Initialize alert indices before rules; rule API keys inherit this account's privileges.
    kibana.request("POST", "/api/detection_engine/index", {})
    rules = [json.loads(line) for line in (ROOT / "rules/elastic/rules.ndjson").read_text().splitlines()]
    for rule in rules:
        try:
            kibana.request("GET", "/api/detection_engine/rules?rule_id=" + rule["rule_id"])
        except ApiError as exc:
            if exc.status != 404:
                raise
            kibana.request("POST", "/api/detection_engine/rules", rule)
        else:
            kibana.request("PUT", "/api/detection_engine/rules", rule)
    count = import_objects(kibana, ROOT / "dashboards/purplelab.ndjson")
    print(f"Provisioned {len(rules)} rules and {count} saved objects. Lab ready at https://localhost:5601")
