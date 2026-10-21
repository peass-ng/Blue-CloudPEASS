"""Reviewed purpose of each check, separate from engine scan categories."""
from functools import lru_cache
import json
from pathlib import Path


@lru_cache(maxsize=1)
def registry():
    data = json.loads((Path(__file__).parent / "checks/finding_types.json").read_text())
    ids = [row["id"] for row in data["types"]]
    if data.get("schema_version") != 1 or len(ids) != len(set(ids)) or "unclassified" in ids:
        raise ValueError("Invalid finding type taxonomy")
    if any(value not in ids for value in data["checks"].values()):
        raise ValueError("Check has an unknown finding type")
    return data


def type_for(check_id, category=None):
    from peaso.checks import resolve_check_id
    value = registry()["checks"].get(resolve_check_id(check_id))
    # Technique findings all evaluate permissions and privilege paths. Older
    # catalogs can contain technique IDs absent from today's native registry.
    return value or ("permissions" if category == "privesc" else "unclassified")


def label_for(type_id):
    return next((row["label"] for row in registry()["types"] if row["id"] == type_id), "Unclassified")


@lru_cache(maxsize=1)
def type_ids():
    return frozenset(row["id"] for row in registry()["types"])


def annotate(finding):
    """Presentation metadata can also be attached to historical report indexes."""
    value = type_for(finding.get("check_id"), finding.get("category"))
    if value == "unclassified" and finding.get("finding_type") in type_ids():
        value = finding["finding_type"]
    return dict(finding, finding_type=value)


def validate_review(check_ids):
    from peaso.analysis import MANUAL_ONLY_ANALYSIS_CHECK_IDS
    expected, reviewed = set(check_ids) | MANUAL_ONLY_ANALYSIS_CHECK_IDS, set(registry()["checks"])
    if expected != reviewed:
        raise ValueError(f"Finding type review differs from registered checks: missing={sorted(expected-reviewed)}, stale={sorted(reviewed-expected)}")
