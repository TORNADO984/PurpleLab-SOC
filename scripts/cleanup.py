"""Stop this Compose project; require an explicit typed confirmation to delete volumes."""
import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--purge", action="store_true")
args = parser.parse_args()
command = ["docker", "compose", "--profile", "tools", "--profile", "filebeat", "down", "--remove-orphans"]
if args.purge:
    if input("Type PURGE to destroy this lab evidence and credentials: ") != "PURGE":
        raise SystemExit("Cancelled")
    command.append("--volumes")
raise SystemExit(subprocess.call(command, cwd=Path(__file__).resolve().parents[1]))
