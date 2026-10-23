"""Run the exact named cases still missing recorded AWS route graph execution.

The TSV remains the source of truth. This command writes JUnit evidence and does
not edit or promote any route; inspect the test bodies and results before doing so.
"""

import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CASES = Path(__file__).with_name("route-case-coverage.tsv")
CASE_REF = re.compile(r"tests/[\w.-]+\.py(?:::[\w]+)*::test_[\w]+")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--basetemp", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--list-only", action="store_true")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    with CASES.open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    refs = sorted({ref for row in rows if row["status"] == "partial"
                   for kind in ("positive", "negative", "unknown")
                   for ref in CASE_REF.findall(row[f"{kind}_case"])})
    if not refs:
        parser.error("the case ledger has no partial routes")
    missing = [ref for ref in refs if not (ROOT / ref.split("::", 1)[0]).is_file()]
    if missing:
        parser.error(f"named test files are missing: {missing}")
    print(f"{sum(row['status'] == 'partial' for row in rows)} partial routes; "
          f"{len(refs)} distinct named test nodes", flush=True)
    if args.list_only:
        for ref in refs:
            print(ref)
        return
    args.junit.parent.mkdir(parents=True, exist_ok=True)
    args.basetemp.parent.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
               "--junitxml", str(args.junit), "--basetemp", str(args.basetemp)]
    if args.workers > 1:
        command.extend(("-n", str(args.workers), "--dist", "loadfile"))
    command.extend(refs)
    raise SystemExit(subprocess.call(command, cwd=ROOT))


if __name__ == "__main__":
    main()
