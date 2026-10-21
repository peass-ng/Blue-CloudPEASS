"""Report the individual AWS recovery review against HackTricks Cloud's current pages."""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RETIRED_STATES = {"pending", "triaged", "candidate", "excluded_verified", "implemented"}
PAGE_STATES = {"pending", "triaged", "reviewed"}


def rows(name):
    with (ROOT / name).open(newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--book-root", type=Path, required=True)
    args = parser.parse_args()

    retired = rows("retired-technique-status.tsv")
    pages = rows("page-status.tsv")
    ids = [row["id"] for row in retired]
    if len(ids) != 362 or len(set(ids)) != len(ids):
        raise SystemExit("Retired cohort must contain 362 unique original technique IDs")
    invalid = [row["id"] for row in retired if row["review_state"] not in RETIRED_STATES
               or (row["review_state"] != "pending" and row["review_evidence"].strip() in ("", "-"))]
    if invalid:
        raise SystemExit(f"Invalid retired review rows: {invalid[:10]}")

    page_root = args.book_root / "src/pentesting-cloud/aws-security/aws-privilege-escalation"
    actual = {path.relative_to(args.book_root).as_posix() for path in page_root.rglob("*.md")}
    recorded = [row["page"] for row in pages]
    if set(recorded) != actual or len(recorded) != len(actual):
        raise SystemExit(f"Page tracker mismatch: missing={sorted(actual - set(recorded))}, "
                         f"stale={sorted(set(recorded) - actual)}")
    invalid = [row["page"] for row in pages if row["review_state"] not in PAGE_STATES
               or (row["review_state"] != "pending" and row["review_evidence"].strip() in ("", "-"))]
    if invalid:
        raise SystemExit(f"Invalid page review rows: {invalid[:10]}")

    print("Retired techniques:", dict(sorted(Counter(row["review_state"] for row in retired).items())))
    print("Privesc pages:", dict(sorted(Counter(row["review_state"] for row in pages).items())))


if __name__ == "__main__":
    main()
