"""Export current inert fixtures for optional Filebeat ingestion."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from purplelab.events import generate  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("scenario")
parser.add_argument("output", type=Path)
args = parser.parse_args()
run_id, events = generate(args.scenario)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
print(f"Exported {len(events)} events; run_id={run_id}; output={args.output}")
