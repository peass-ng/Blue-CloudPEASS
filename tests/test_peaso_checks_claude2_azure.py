"""Shard integrity for the claude2_azure partition, validated in memory without regenerating central artifacts."""
import copy
import json
from pathlib import Path

import pytest

import peaso.checks.claude2_azure  # noqa: F401  (registers every claude2_azure group)
from peaso.checks import CHECKS, HACKTRICKS
from peaso.checks.claude2_azure_common import CHECK_IDS, PREFIX
from peaso.checks.fixtures import CASES

PACK = Path(__file__).resolve().parent.parent / "peaso" / "rulepacks"
REVIEWED = json.loads((PACK / "reviewed_claude2_azure.json").read_text())
MANUAL = json.loads((PACK / "reviewed_claude2_azure_manual.json").read_text())
PARTITION = set(json.loads((PACK / "port_partitions_claude2.json").read_text())["partitions"]["claude2_azure"]["check_ids"])
MANIFEST = {row["check_id"]: row for row in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}
REGISTRY = {check.id: check for check in CHECKS}
LEFTOVERS = {"azure-compliance.control.network_sg_flowlog_enabled",
             "azure-compliance.control.network_sg_flowlog_retention_period_greater_than_90",
             "azure-compliance.control.nsg_network_watcher_flow_log_send_to_log_analytics"}
# reviewed_claude_azure.json rejects the MMK leftover (deferral lifted by the supervisor); its rejection wins.
HELD_ELSEWHERE = {"azure-compliance.control.storage_account_encryption_at_rest_using_mmk"}


def _active_reviews():
    config = json.loads((PACK / "active_reviews.json").read_text())
    merged = {}
    for name in config["shards"]:
        if name.startswith("reviewed_claude2_azure"):
            continue
        deferred = config.get("deferred_source_ids", {}).get(name, {})
        for key, value in json.loads((PACK / name).read_text()).items():
            if key not in deferred:
                merged.setdefault(key, []).append(value["disposition"])
    return merged


def test_shards_cover_partition_minus_rows_owned_by_active_shards():
    assert not set(REVIEWED) & set(MANUAL)
    others = _active_reviews()
    mine = {**REVIEWED, **MANUAL}
    for key, entry in mine.items():
        assert key in PARTITION and key in MANIFEST, key
        if key in others:
            assert entry.get("supersedes") == key and set(others[key]) == {"pending"}, key
        else:
            assert "supersedes" not in entry, key
    assert not HELD_ELSEWHERE & set(mine)
    claude_azure = json.loads((PACK / "reviewed_claude_azure.json").read_text())
    assert all(claude_azure[key]["disposition"] == "rejected" for key in HELD_ELSEWHERE)
    for key in PARTITION - set(mine) - HELD_ELSEWHERE:
        assert any(d != "pending" for d in others.get(key, [])), "unreviewed partition row: " + key
    assert len(PARTITION) - len(mine) == 114
    for key in LEFTOVERS:
        assert mine[key]["disposition"] == "ported" and "supersedes" not in mine[key] and "VNet flow log" in mine[key]["review_notes"], key


def test_supported_rows_reference_registered_predicates():
    for key, entry in REVIEWED.items():
        assert entry["disposition"] in ("ported", "merged", "rejected"), key
        assert entry["reason"] and entry["official_docs"], key
        assert all(url.startswith("https://learn.microsoft.com/") for url in entry["official_docs"]), key
        if entry["disposition"] == "rejected":
            assert entry["native_checks"] == [], key
        else:
            assert entry["native_checks"] and all(cid in REGISTRY for cid in entry["native_checks"]), key
            if entry["disposition"] == "ported":
                assert any(cid.startswith(PREFIX) for cid in entry["native_checks"]), key


def test_manual_rows_preserve_upstream_question():
    for key, entry in MANUAL.items():
        assert entry["disposition"] == "rejected" and entry["native_checks"] == [], key
        assert entry["review_classification"] == "manual_attestation", key
        assert entry["manual_requirement"]["question"] == MANIFEST[key]["title"], key


def test_orphaned_predicates_were_removed():
    slug = PREFIX + "storage_account_microsoft_managed_keys"
    assert slug not in REGISTRY and slug not in CASES


def test_every_claude2_predicate_is_claimed():
    claimed = {cid for entry in REVIEWED.values() for cid in entry["native_checks"]}
    assert set(CHECK_IDS) <= claimed, sorted(set(CHECK_IDS) - claimed)


def test_no_predicate_iterates_builtin_role_definitions_per_subscription():
    role_checks = [REGISTRY[c] for c in CHECK_IDS if REGISTRY[c].kind == "role_definition"]
    assert role_checks and all(check.target == "scope" for check in role_checks)


@pytest.mark.parametrize("cid", CHECK_IDS)
def test_predicate_contract(cid):
    check = REGISTRY[cid]
    assert check.provider == "azure" and HACKTRICKS in check.frameworks
    assert check.remediation and check.dependencies
    cases = CASES[cid]
    assert "pass" in cases and "fail" in cases
    assert check.evaluate(cases.get("missing", {}), cases.get("pass_index", {}))[0] == "UNKNOWN"
    assert check.evaluate(None, {})[0] == "UNKNOWN"
    assert check.evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_in_memory_manifest_with_claude2_reviews_validates():
    from scripts.peaso_review_catalog import validate_manifest
    claude_azure = json.loads((PACK / "reviewed_claude_azure.json").read_text())
    rows = []
    for key, row in MANIFEST.items():
        row = copy.deepcopy(row)
        review = REVIEWED.get(key) or MANUAL.get(key) or (claude_azure[key] if key in HELD_ELSEWHERE else None)
        if review is not None:
            row.update({k: v for k, v in review.items() if k != "supersedes"})
        rows.append(row)
    stats = validate_manifest({"checks": rows})
    assert stats["native_checks"] == len(CHECKS)
