"""Validate the per-technique review tracker against the active catalog."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from peaso import privesc


ROOT = Path(__file__).resolve().parents[1]
TRACKER = ROOT / "docs/evidence-reviews/privesc-technique-progress.json"
SOURCE_REVIEWS = ROOT / "docs/evidence-reviews/privesc.json"
PROVIDERS = {"gcp", "azure", "k8s"}


def main() -> int:
    report = json.loads(TRACKER.read_text())
    source_reviews = json.loads(SOURCE_REVIEWS.read_text())["checks"]
    recorded = report["techniques"]
    current = {
        entry["id"]: entry
        for entry in privesc.catalog()["entries"]
        if entry["provider"] in PROVIDERS
    }
    by_id = {entry["id"]: entry for entry in recorded}
    retired = report.get("retired_techniques", [])
    retired_ids = {entry["id"] for entry in retired}
    errors = []
    if len(by_id) != len(recorded):
        errors.append("duplicate technique IDs in tracker")
    if len(retired_ids) != len(retired):
        errors.append("duplicate retired technique IDs in tracker")
    for ident in sorted(retired_ids & current.keys()):
        errors.append(f"retired technique still active: {ident}")
    for entry in retired:
        if entry.get("status") != "retired" or not entry.get("completion_evidence"):
            errors.append(f"retired technique lacks review evidence: {entry.get('id')}")
    for ident in sorted(current.keys() - by_id.keys()):
        errors.append(f"missing: {ident}")
    for ident in sorted(by_id.keys() - current.keys()):
        errors.append(f"inactive: {ident}")
    for ident in sorted(current.keys() & by_id.keys()):
        entry = {key: value for key, value in current[ident].items() if not key.startswith("_")}
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        tracked = by_id[ident]
        if tracked["current_contract_sha256"] != digest:
            errors.append(f"changed catalog entry: {ident}")
        source_review = source_reviews.get(ident)
        stale_pending = (tracked.get("status") == "pending" and
                         tracked.get("source_contract_review") == "needs_re_review" and
                         source_review is not None and
                         source_review.get("reviewed_contract_sha256") != digest)
        if (not stale_pending and
                (tracked.get("source_contract_review") != "record_matches_current_yaml"
                 or source_review is None or source_review.get("reviewed_contract_sha256") != digest)):
            errors.append(f"source review missing or outdated: {ident}")
        if tracked["checked"] != (tracked["status"] == "completed"):
            errors.append(f"inconsistent checked status: {ident}")
        if tracked["status"] not in {"pending", "in_progress", "completed"}:
            errors.append(f"invalid status: {ident}")
        if tracked["status"] == "completed" and not tracked.get("completion_evidence"):
            errors.append(f"completed without evidence: {ident}")
    counts = Counter(entry["status"] for entry in recorded)
    if {status: counts[status] for status in ("completed", "in_progress", "pending")} != report["counts"]:
        errors.append("summary counts do not match technique rows")
    print(f"GCP: {sum(e['provider'] == 'gcp' for e in recorded)}; "
          f"Azure: {sum(e['provider'] == 'azure' for e in recorded)}; "
          f"Kubernetes: {sum(e['provider'] == 'k8s' for e in recorded)}")
    print(f"Completed: {counts['completed']}; in progress: {counts['in_progress']}; "
          f"pending: {counts['pending']}")
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
