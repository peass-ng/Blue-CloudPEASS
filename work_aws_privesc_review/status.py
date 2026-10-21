"""Validate the AWS technique review record against the active catalog."""
from __future__ import annotations

import csv
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from peaso import privesc


def main() -> None:
    path = Path(__file__).with_name("technique-status.tsv")
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    ids = [row["id"] for row in rows]
    active = {entry["id"] for entry in privesc.catalog()["entries"] if entry["provider"] == "aws"}
    duplicates = sorted({ident for ident in ids if ids.count(ident) > 1})
    missing = sorted(active - set(ids))
    stale = sorted(set(ids) - active)
    invalid = [row["id"] for row in rows if row["status"] not in ("checked", "checked_previous", "pending")
               or row["status"] != "pending" and not row["review_evidence"].strip()]
    if duplicates or missing or stale or invalid:
        raise SystemExit(f"Invalid review status: duplicates={duplicates}, missing={missing}, "
                         f"stale={stale}, invalid={invalid}")
    current = sum(row["status"] == "checked" for row in rows)
    previous = sum(row["status"] == "checked_previous" for row in rows)
    print(f"AWS active: {len(active)}; reviewed at least once: {current + previous}; "
          f"current sign-off: {current}; older review only: {previous}; never reviewed: "
          f"{len(active) - current - previous}; remaining for current sign-off: {len(active) - current}")
    for row in rows:
        if row["status"] != "checked":
            print(f"{row['status']}\t{row['id']}")


if __name__ == "__main__":
    main()
