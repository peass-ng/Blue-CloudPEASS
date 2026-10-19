"""Validate every check's primary type and reproduce its human-readable review."""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def outputs():
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS
    from peaso.finding_types import registry, label_for, validate_review
    metadata = {c.id: {"provider": c.provider, "title": c.title} for c in CHECKS}
    metadata.update({c["id"]: c for c in ANALYSIS_CHECKS})
    validate_review(metadata)
    data = registry()
    reasons = {row["id"]: row["description"] for row in data["types"]}
    rows = [{"check_id": cid, "provider": metadata[cid]["provider"], "title": metadata[cid]["title"],
             "finding_type": typ, "label": label_for(typ), "purpose": reasons[typ]}
            for cid, typ in sorted(data["checks"].items())]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return rows, {ROOT / "docs/finding-type-review.csv": stream.getvalue(),
                  ROOT / "frontend/src/findingTypes.json": json.dumps(data["types"], indent=2) + "\n"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    rows, files = outputs()
    stale = [str(path.relative_to(ROOT)) for path, text in files.items() if not path.exists() or path.read_text() != text]
    if args.write:
        for path, text in files.items():
            path.write_text(text)
    print(json.dumps({"reviewed": len(rows), "counts": dict(sorted(Counter(row["finding_type"] for row in rows).items())),
                      "stale": [] if args.write else stale}))
    return int(bool(stale) and not args.write)


if __name__ == "__main__":
    raise SystemExit(main())
