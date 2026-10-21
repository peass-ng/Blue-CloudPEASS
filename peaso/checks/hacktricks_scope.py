"""Explicit checklist membership, independent of upstream compliance mappings.

New checks are untagged until reviewed. Never infer membership from a service,
category, source framework, title keyword, or the presence of a HackTricks link.
"""
from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def review():
    data = json.loads(Path(__file__).with_name("hacktricks_scope.json").read_text())
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported HackTricks checklist review")
    for check_id, row in data["checks"].items():
        if row["decision"] not in ("include", "exclude", "pending") or row["group"] not in data["groups"]:
            raise ValueError("Invalid HackTricks checklist decision: " + check_id)
    return data


def includes(check_id):
    from . import resolve_check_id
    row = review()["checks"].get(resolve_check_id(check_id))
    return row is not None and row["decision"] == "include"


def validate_review(check_ids):
    """Build/test gate: every registered check needs an explicit decision."""
    from peaso.analysis import MANUAL_ONLY_ANALYSIS_CHECK_IDS
    expected, reviewed = set(check_ids) | MANUAL_ONLY_ANALYSIS_CHECK_IDS, set(review()["checks"])
    missing, stale = expected - reviewed, reviewed - expected
    pending = sorted(cid for cid, row in review()["checks"].items() if row["decision"] == "pending")
    if missing or stale or pending:
        raise ValueError(f"Incomplete HackTricks checklist review: missing={sorted(missing)}, stale={sorted(stale)}, pending={pending}")
