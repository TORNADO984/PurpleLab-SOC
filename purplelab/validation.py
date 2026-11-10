"""Run-scoped end-to-end checks against actual Elastic Security alerts."""
import time
from datetime import datetime, timezone

from .client import ApiError, Client
from .events import catalog, generate, get_field


def assess_alerts(hits, expected, run_id, positive_ids, negative_ids):
    """Reject negative controls and count only the intended rule/event pair."""
    seen, unexpected = set(), []
    for hit in hits:
        source = hit["_source"]
        if get_field(source, "purplelab.run_id") != run_id:
            continue
        rule_id = get_field(source, "kibana.alert.rule.rule_id")
        if rule_id not in {c["uuid"] for c in catalog()}:
            continue
        event_id = get_field(source, "event.id")
        case_id = get_field(source, "purplelab.case_id")
        if event_id in negative_ids or get_field(source, "purplelab.expected_match") is False:
            unexpected.append({"rule_id": rule_id, "case_id": case_id, "event_id": event_id})
        if (case_id in expected and expected[case_id] == rule_id
                and positive_ids.get(case_id) == event_id):
            seen.add(rule_id)
    return seen, unexpected


def execution_after(kibana, rule_ids, started):
    healthy, errors = set(), {}
    for rule_id in rule_ids:
        rule = kibana.request("GET", "/api/detection_engine/rules?rule_id=" + rule_id)
        last = rule.get("execution_summary", {}).get("last_execution", {})
        if last.get("status") in ("failed", "partial failure"):
            errors[rule_id] = last.get("message", last.get("status"))
        if last.get("status") == "succeeded" and last.get("date", "") >= started:
            healthy.add(rule_id)
    return healthy, errors


def validate(scenario="all", timeout=300):
    from .cli import event_index

    run_id, positive = generate(scenario)
    _, negative = generate(scenario, negative=True, run_id=run_id)
    selected = [c for c in catalog() if scenario == "all" or c["scenario"] == scenario]
    expected = {c["id"]: c["uuid"] for c in selected}
    positive_ids = {e["purplelab"]["case_id"]: e["event"]["id"] for e in positive}
    negative_ids = {e["event"]["id"] for e in negative}
    writer, reader, kibana = Client(username="event_writer"), Client(), Client("kibana")
    writer.bulk(positive + negative, event_index())
    started = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    begin = time.monotonic()
    seen, unexpected, healthy, errors = set(), [], set(), {}
    # Observe at least a complete scheduler interval plus indexing slack.
    # A missing or failed execution can never count as a clean negative result.
    while time.monotonic() - begin < timeout:
        try:
            result = reader.request("POST", "/.alerts-security.alerts-default/_search", {
                "size": 10000, "track_total_hits": True,
                "query": {"terms": {"event.id": sorted(set(positive_ids.values()) | negative_ids)}},
                "_source": ["kibana.alert.rule.rule_id", "event.id", "purplelab"],
            })
        except ApiError as exc:
            if exc.status != 404:
                raise
            time.sleep(5)
            continue
        hits = result["hits"]["hits"]
        if result["hits"]["total"]["value"] > len(hits):
            raise RuntimeError("Alert response truncated; refusing incomplete validation")
        seen, unexpected = assess_alerts(hits, expected, run_id, positive_ids, negative_ids)
        if unexpected:
            break
        if time.monotonic() - begin >= 90 and seen == set(expected.values()):
            healthy, errors = execution_after(kibana, expected.values(), started)
            if healthy == set(expected.values()):
                break
        time.sleep(5)
    if not healthy:
        healthy, errors = execution_after(kibana, expected.values(), started)
    passed = (seen == set(expected.values()) and not unexpected
              and healthy == set(expected.values()) and time.monotonic() - begin >= 90)
    missing = [c["id"] for c in selected if c["uuid"] not in seen]
    report = {
        "passed": passed, "run_id": run_id, "scenario": scenario,
        "positive_events": len(positive), "negative_events": len(negative),
        "expected_rules": len(expected), "observed_rules": len(seen), "missing": missing,
        "negative_alerts": unexpected, "successful_rule_executions": len(healthy),
        "execution_errors": errors, "observation_seconds": round(time.monotonic() - begin, 1),
    }
    now = datetime.now(timezone.utc).isoformat()
    for case in selected:
        status = "passed" if (passed and case["uuid"] in seen) else "failed"
        reader.request("PUT", "/purplelab-validation/_doc/" + run_id + "-" + case["id"], {
            "@timestamp": now, "run_id": run_id, "rule_id": case["uuid"],
            "technique": case["technique"], "scenario": case["scenario"], "status": status, "synthetic": True,
        })
    reader.request("POST", "/purplelab-validation/_refresh")
    return report
