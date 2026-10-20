"""Validate explicit HackTricks checklist decisions and export the review receipt."""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def audit():
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS, HACKTRICKS
    from peaso.checks.hacktricks_scope import includes, review, validate_review
    from peaso.checks.native_only import automated_checks

    policy = review()
    registered = {c.id: c for c in CHECKS}
    projections = {c["id"]: c for c in ANALYSIS_CHECKS}
    validate_review(set(registered) | set(projections))
    active = {c.id for c in automated_checks(CHECKS)} | set(projections)
    rows = []
    for cid, decision in sorted(policy["checks"].items()):
        check = registered.get(cid)
        metadata = {"provider": check.provider, "title": check.title} if check else projections[cid]
        names = check.frameworks if check else metadata["frameworks"]
        mapping = check.mapping if check else metadata["mapping"]
        if ((HACKTRICKS in names) != includes(cid) or
                (HACKTRICKS in mapping if check else bool(mapping)) != includes(cid)):
            raise ValueError("HackTricks label/mapping differs from review: " + cid)
        rows.append({"check_id": cid, "provider": metadata["provider"], "title": metadata["title"],
                     "active": cid in active, **decision,
                     "reason": policy["groups"][decision["group"]]["rationale"]})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write the per-check CSV review receipt")
    args = parser.parse_args(argv)
    rows = audit()
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    path = ROOT / "docs/hacktricks-checklist-review.csv"
    payload = buffer.getvalue()
    stale = not path.exists() or path.read_text() != payload
    if args.write:
        path.write_text(payload)
    print(json.dumps({"reviewed": len(rows), "decisions": dict(Counter(r["decision"] for r in rows)),
                      "active_decisions": dict(Counter(r["decision"] for r in rows if r["active"])),
                      "pending": sum(r["decision"] == "pending" for r in rows),
                      "receipt_current": args.write or not stale}))
    return 0 if args.write or not stale else 1


if __name__ == "__main__":
    raise SystemExit(main())
