"""Administrative and synthetic-telemetry CLI; no attack execution facility."""

import argparse
import json
import sys
from datetime import datetime, timezone

from .client import Client, secret
from .events import catalog, generate


def main(argv=None):
    parser = argparse.ArgumentParser(description="PurpleLab-SOC: authorized synthetic detection validation")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init-secrets", "setup-security", "provision", "credentials", "list"):
        sub.add_parser(command)
    gen = sub.add_parser("generate", help="Generate inert event JSON or ingest it into the lab")
    gen.add_argument("--scenario", default="all")
    gen.add_argument("--negative", action="store_true", help="Generate benign near-miss controls")
    gen.add_argument("--dry-run", action="store_true", help="Print NDJSON without credentials or network access")
    val = sub.add_parser("validate", help="Generate fixtures and require real Elastic detection alerts")
    val.add_argument("--scenario", default="all")
    val.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        if args.command in ("init-secrets", "setup-security", "provision"):
            from . import provision
            getattr(provision, args.command.replace("-", "_"))()
        elif args.command == "credentials":
            print(json.dumps({user: secret(user) for user in
                              ("elastic", "soc_analyst", "detection_engineer", "beats_writer")}, indent=2))
        elif args.command == "list":
            for name in sorted({c["scenario"] for c in catalog()}):
                print(name)
        elif args.command == "generate":
            run_id, events = generate(args.scenario, args.negative)
            if args.dry_run:
                for event in events:
                    print(json.dumps(event))
            else:
                count = Client(username="event_writer").bulk(events, event_index())
                print(json.dumps({"run_id": run_id, "events": count, "negative": args.negative}))
        elif args.command == "validate":
            if not 100 <= args.timeout <= 600:
                parser.error("--timeout must be between 100 and 600 seconds")
            from .validation import validate
            report = validate(args.scenario, args.timeout)
            print(json.dumps(report, indent=2))
            return 0 if report["passed"] else 1
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"PurpleLab error: {exc}", file=sys.stderr)
        return 1


def event_index():
    return "purplelab-events-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
