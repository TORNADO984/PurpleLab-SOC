"""Content contracts and regression tests; scheduled alerts are checked separately."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from purplelab.cli import main
from purplelab.client import ApiError, Client
from purplelab.events import ROOT, catalog, generate, get_field, make_event
from purplelab.validation import assess_alerts, execution_after
from scripts.build_content import FIELD_MAP, convert


def sigma_matches(case, event):
    """Independent evaluation of the catalog's restricted Sigma selection semantics."""
    for key, expected in case["selection"].items():
        field, *modifiers = key.split("|")
        actual = get_field(event, FIELD_MAP.get(field, "winlog.event_data." + field))
        values = expected if isinstance(expected, list) else [expected]
        actual = str(actual).lower()
        if "contains" in modifiers:
            results = [str(value).lower() in actual for value in values]
        elif "endswith" in modifiers:
            results = [actual.endswith(str(value).lower()) for value in values]
        else:
            results = [actual == str(value).lower() for value in values]
        if not (all(results) if "all" in modifiers else any(results)):
            return False
    return get_field(event, "event.provider") == case["positive"]["event.provider"]


class ContentTests(unittest.TestCase):
    def test_rule_pairs_and_all_negative_controls(self):
        cases = catalog()
        self.assertEqual(len(cases), 20)
        native = [json.loads(line) for line in (ROOT / "rules/elastic/rules.ndjson").read_text().splitlines()]
        self.assertEqual(len({c["uuid"] for c in cases}), 20)
        for case, rule in zip(cases, native):
            sigma = yaml.safe_load((ROOT / "rules/sigma" / (case["id"] + ".yml")).read_text())
            self.assertEqual(sigma["id"], rule["rule_id"])
            self.assertEqual(sigma["detection"]["selection"], case["selection"])
            self.assertNotIn("purplelab", rule["query"].lower().replace(".purplelab.test", ""))
            self.assertTrue(sigma_matches(case, make_event(case, "test")), case["id"])
            for negative in cases:
                self.assertFalse(sigma_matches(case, make_event(negative, "test", True)),
                                 f"{case['id']} matches negative {negative['id']}")

    def test_scenarios_cover_exactly_all_rules(self):
        paths = list((ROOT / "scenarios").glob("*.yml"))
        self.assertEqual(len(paths), 8)
        covered = []
        for path in paths:
            data = yaml.safe_load(path.read_text())
            covered.extend(data["expected_rules"])
            self.assertGreaterEqual(len(data["playbook"]), 6)
            self.assertTrue(path.with_suffix(".md").exists())
        self.assertEqual(set(covered), {c["uuid"] for c in catalog()})
        self.assertEqual(len(covered), 20)

    def test_offline_generation_and_unknown_scenario(self):
        output = io.StringIO()
        with patch("purplelab.cli.Client", side_effect=AssertionError("Network used")), contextlib.redirect_stdout(output):
            self.assertEqual(main(["generate", "--dry-run"]), 0)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(events), 20)
        self.assertEqual(len({e["event"]["id"] for e in events}), 20)
        self.assertTrue(all(e["purplelab"]["synthetic"] for e in events))
        with self.assertRaises(ValueError):
            generate("unknown")

    def test_dashboard_references_resolve(self):
        objects = [json.loads(line) for line in (ROOT / "dashboards/purplelab.ndjson").read_text().splitlines()]
        keys = {(o["type"], o["id"]) for o in objects}
        self.assertEqual(len(keys), len(objects))
        for item in objects:
            for ref in item["references"]:
                self.assertIn((ref["type"], ref["id"]), keys)
        self.assertEqual(sum(o["type"] == "dashboard" for o in objects), 3)

    def test_converter_fails_on_unsupported_sigma(self):
        with self.assertRaises(ValueError):
            convert({"Image|re": ".*"}, "test")

    def test_bulk_errors_are_not_success(self):
        client = Client.__new__(Client)
        with patch.object(client, "request", return_value={"errors": True, "items": [{"create": {"error": "denied"}}]}):
            with self.assertRaisesRegex(RuntimeError, "Bulk ingestion failed"):
                client.bulk([make_event(catalog()[0], "test")], "purplelab-events-test")

    def test_validator_ignores_stale_and_wrong_pairs(self):
        case = catalog()[0]
        expected = {case["id"]: case["uuid"]}
        event = make_event(case, "old-run")
        event["kibana.alert.rule.rule_id"] = case["uuid"]
        seen, _ = assess_alerts([{"_source": event}], expected, "new-run", {case["id"]: event["event"]["id"]}, set())
        self.assertEqual(seen, set())
        event["purplelab"]["run_id"] = "new-run"
        seen, _ = assess_alerts([{"_source": event}], expected, "new-run", {case["id"]: "different-event"}, set())
        self.assertEqual(seen, set())

    def test_validation_searches_indexed_event_ids(self):
        source = (ROOT / "purplelab/validation.py").read_text()
        self.assertIn('"terms": {"event.id":', source)
        self.assertNotIn('"term": {"purplelab.run_id":', source)

    def test_validator_flags_negative_and_accepts_exact_pair(self):
        case = catalog()[0]
        event = make_event(case, "run")
        event["kibana.alert.rule.rule_id"] = case["uuid"]
        args = ({case["id"]: case["uuid"]}, "run", {case["id"]: event["event"]["id"]}, set())
        seen, bad = assess_alerts([{"_source": event}], *args)
        self.assertEqual(seen, {case["uuid"]})
        self.assertFalse(bad)
        event["purplelab"]["expected_match"] = False
        _, bad = assess_alerts([{"_source": event}], *args)
        self.assertEqual(len(bad), 1)

    def test_failed_and_stale_executions_do_not_pass(self):
        with patch("purplelab.validation.Client") as kb:
            kb.request.return_value = {"execution_summary": {"last_execution": {
                "status": "succeeded", "date": "2026-01-01T00:00:00Z"}}}
            healthy, _ = execution_after(kb, ["rule"], "2026-11-10T00:00:00Z")
            self.assertFalse(healthy)
            kb.request.side_effect = ApiError(403, "forbidden")
            with self.assertRaises(ApiError):
                execution_after(kb, ["rule"], "2026-11-10T00:00:00Z")

    def test_secrets_are_persistent_and_not_printed(self):
        from purplelab.provision import init_secrets
        scratch = ROOT / "artifacts"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temp:
            root = Path(temp)
            output = io.StringIO()
            with patch.dict("os.environ", {"PURPLELAB_STATE": str(root / "state"),
                                           "PURPLELAB_WRITER_STATE": str(root / "writer")}), contextlib.redirect_stdout(output):
                init_secrets()
                value = (root / "state/elastic").read_text()
                init_secrets()
            self.assertEqual((root / "state/elastic").read_text(), value)
            self.assertGreaterEqual(len(value.strip()), 32)
            self.assertNotIn(value.strip(), output.getvalue())


if __name__ == "__main__":
    unittest.main()
