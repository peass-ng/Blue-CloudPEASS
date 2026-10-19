"""AWS upstream-gap audit: corrected native predicates and their framework links."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks import aws_gap_core as gap
from peaso.checks.fixtures import CASES

PACK = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks"
REGISTRY = {check.id: check for check in CHECKS}
SHARD = json.loads((PACK / "reviewed_aws_gap.json").read_text())
EXPECTED = {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN", "not_applicable": "NOT_APPLICABLE"}


def _manifest():
    return {row["check_id"]: row for row in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}


def _evaluate(cid, item, index):
    item_copy, index_copy = copy.deepcopy(item), copy.deepcopy(index)
    status = REGISTRY[cid].evaluate(item_copy, index_copy)[0]
    assert item_copy == item and index_copy == index, f"{cid} mutated its inputs"
    return status


def test_gap_natives_registered_with_prefix():
    assert len(gap.NATIVE_IDS) == len(set(gap.NATIVE_IDS)) == 18
    for cid in gap.NATIVE_IDS:
        assert cid.startswith("aws.gap.") and cid in REGISTRY


@pytest.mark.parametrize("cid", gap.NATIVE_IDS)
def test_gap_behaviour_fixtures(cid):
    case = CASES[cid]
    assert {"pass", "fail"} <= set(case)
    default = case.get("index", {})
    for name, expected in EXPECTED.items():
        if name in case:
            assert _evaluate(cid, case[name], case.get(f"{name}_index", default)) == expected, (cid, name)
    for expected, item, index in case.get("variants", []):
        assert _evaluate(cid, item, default if index is None else index) == expected, cid


@pytest.mark.parametrize("cid", gap.NATIVE_IDS)
def test_gap_missing_or_denied_facts_never_pass(cid):
    default = CASES[cid].get("index", {})
    for item in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[cid].evaluate(item, default)[0] == "UNKNOWN"


def test_management_coverage_rejects_event_source_filters():
    trail = copy.deepcopy(gap.TRAIL)
    trail["EventSelectors"] = {"collection_status": "collected", "TrailARN": trail["TrailARN"], "AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Management"]},
        {"Field": "eventSource", "Equals": ["s3.amazonaws.com"]},
    ]}]}
    read, write, _ = gap.management_coverage(trail)
    assert not (read and write)


def test_s3_all_bucket_coverage_rejects_arn_filters():
    trail = copy.deepcopy(gap.TRAIL)
    trail["EventSelectors"] = {"collection_status": "collected", "TrailARN": trail["TrailARN"], "AdvancedEventSelectors": [{"FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
        {"Field": "resources.ARN", "StartsWith": ["arn:aws:s3:::only-this/"]},
    ]}]}
    assert gap.s3_data_coverage(trail, None, "aws") == (False, False)
    assert gap.s3_data_coverage(trail, "only-this", "aws") == (True, True)


def test_shard_entries_reference_registered_natives_and_keep_provenance():
    assert len(SHARD) == 337
    for key, entry in SHARD.items():
        assert key.startswith(("aws-compliance.", "prowler.", "aws-perimeter.")), key
        assert entry["disposition"] in {"ported", "merged"}
        assert entry["native_checks"] and all(native in REGISTRY for native in entry["native_checks"]), key
        assert entry["upstream_defect"] and entry["review_history"], key
        if entry["disposition"] == "ported":
            assert any(native.startswith("aws.gap.") for native in entry["native_checks"]), key


def test_every_gap_native_is_reached_by_the_shard():
    reached = {native for entry in SHARD.values() for native in entry["native_checks"]}
    assert set(gap.NATIVE_IDS) <= reached


def test_superseded_keys_are_deferred_from_their_original_shard():
    active = json.loads((PACK / "active_reviews.json").read_text())
    assert "reviewed_aws_gap.json" in active["shards"]
    deferred = active["deferred_source_ids"]
    for key, entry in SHARD.items():
        origin = entry["review_history"][0]["shard"]
        assert key in deferred.get(origin, {}), (key, origin)


def test_manifest_attaches_upstream_frameworks_to_gap_natives():
    manifest = _manifest()
    for key, entry in SHARD.items():
        row = manifest[key]
        assert row["disposition"] == entry["disposition"]
        assert row["native_checks"] == entry["native_checks"]
        assert row.get("frameworks") is not None


def test_lead_reviewed_rows_merge_only_with_recorded_verification():
    """Lead-reviewed rows are merged only with a verification record (see tests/test_peaso_checks_lead_source_audit.py)."""
    manifest = _manifest()
    for key in ("aws-compliance.control.iam_support_role", "aws-compliance.control.iam_server_certificate_not_expired"):
        entry = SHARD[key]
        assert entry["disposition"] == "merged" and entry["verification"]["native"] in entry["native_checks"]
        assert manifest[key]["native_checks"] == entry["native_checks"]
