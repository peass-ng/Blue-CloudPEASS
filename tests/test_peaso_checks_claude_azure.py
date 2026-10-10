"""Shard integrity for the claude_azure partition, validated in memory without regenerating central artifacts."""
import copy
import json
from pathlib import Path

import pytest

import peaso.checks.claude_azure  # noqa: F401  (registers every claude_azure group)
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.claude_azure_common import CHECK_IDS, PREFIX
from peaso.checks.fixtures import CASES

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude_azure.json").read_text())
MANUAL = json.loads((PACK / "reviewed_claude_azure_manual.json").read_text())
PARTITION = set(json.loads((PACK / "port_partitions_claude.json").read_text())["partitions"]["claude_azure"]["check_ids"])
MANIFEST = {row["check_id"]: row for row in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}
REGISTRY = {check.id: check for check in CHECKS}


def _active_reviews():
    merged = {}
    for name in json.loads((PACK / "active_reviews.json").read_text())["shards"]:
        if name.startswith("reviewed_claude_azure"):
            continue
        merged.update(json.loads((PACK / name).read_text()))
    return merged


def test_shards_are_disjoint_and_inside_partition():
    assert not set(REVIEWED) & set(MANUAL)
    others = _active_reviews()
    for key, entry in {**REVIEWED, **MANUAL}.items():
        assert key in PARTITION, key
        assert key in MANIFEST, key
        if key in others:
            assert entry.get("supersedes") == key and others[key]["disposition"] == "pending", key


def test_supported_rows_reference_registered_claude_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged", "rejected"), key
        assert entry["reason"], key
        if entry["disposition"] == "rejected":
            assert entry["native_checks"] == [], key
            assert entry.get("official_docs") or entry.get("review_notes"), key
        else:
            assert entry["native_checks"], key
            for cid in entry["native_checks"]:
                assert cid in REGISTRY, cid
                if entry["disposition"] == "ported":
                    assert cid.startswith(PREFIX), (key, cid)


def test_manual_rows_preserve_question():
    for key, entry in MANUAL.items():
        assert entry["disposition"] == "rejected" and entry["native_checks"] == [], key
        assert entry["review_classification"] == "manual_attestation", key
        assert entry["manual_requirement"]["question"], key


def test_every_claude_predicate_is_claimed_by_a_review():
    claimed = {cid for entry in REVIEWED.values() for cid in entry["native_checks"]}
    assert set(CHECK_IDS) <= claimed, sorted(set(CHECK_IDS) - claimed)


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_claude_predicate_contract(cid):
    check = REGISTRY[cid]
    assert check.provider == "azure" and HACKTRICKS in check.frameworks
    assert check.remediation and check.dependencies
    cases = CASES[cid]
    assert "pass" in cases and "fail" in cases
    assert check.evaluate(cases.get("missing", {}), cases.get("index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_in_memory_manifest_with_claude_reviews_validates():
    from scripts.peaso_review_catalog import validate_manifest
    rows = []
    for key, row in MANIFEST.items():
        row = copy.deepcopy(row)
        review = REVIEWED.get(key) or MANUAL.get(key)
        if review is not None:
            row.update({k: v for k, v in review.items() if k != "supersedes"})
        rows.append(row)
    stats = validate_manifest({"checks": rows})
    assert stats["native_checks"] == len(CHECKS)
