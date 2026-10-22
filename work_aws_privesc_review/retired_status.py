"""Report the individual AWS recovery review against HackTricks Cloud's current pages."""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

import yaml


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

    additional = rows("additional-technique-status.tsv")
    additional_ids = [row["id"] for row in additional]
    if len(additional_ids) != len(set(additional_ids)) or set(additional_ids) & set(ids):
        raise SystemExit("Additional technique IDs must be unique and outside the original retired cohort")
    catalog_root = args.book_root / "src/privilege-escalation-paths/aws"
    invalid_additional = []
    for row in additional:
        path = catalog_root / row["exclusion_file"]
        if (row["review_state"] not in RETIRED_STATES or
                row["review_evidence"].strip() in ("", "-") or not path.is_file()):
            invalid_additional.append(row["id"])
            continue
        items = yaml.safe_load(path.read_text()) or []
        if not any(item.get("source") == row["source"] and
                   item.get("technique") == row["exclusion_technique"] for item in items):
            invalid_additional.append(row["id"])
    if invalid_additional:
        raise SystemExit(f"Invalid additional technique rows: {invalid_additional}")

    retired_counts = Counter(row["review_state"] for row in retired)
    page_counts = Counter(row["review_state"] for row in pages)
    print("Retired techniques:", dict(sorted(retired_counts.items())))
    print("Retired unresolved:", sum(retired_counts[state] for state in ("pending", "triaged", "candidate")))
    additional_counts = Counter(row["review_state"] for row in additional)
    print("Additional techniques:", dict(sorted(additional_counts.items())))
    print("Additional unresolved:", sum(additional_counts[state] for state in ("pending", "triaged", "candidate")))
    print("Privesc pages:", dict(sorted(page_counts.items())))
    print("Pages awaiting sign-off:", sum(page_counts[state] for state in ("pending", "triaged")))


if __name__ == "__main__":
    main()
