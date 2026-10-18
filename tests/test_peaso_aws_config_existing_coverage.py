"""Coverage-honest recordingStrategy for the existing aws_config_recorder_all_supported_resources.

Real registry check through a sealed Snapshot + engine and a direct MemoIndex call. No network.
"""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks.facts import MemoIndex
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "aws_config_recorder_all_supported_resources"
CHECK = next(check for check in CHECKS if check.id == CID)
SCOPE = "123456789012/us-east-1"
ALL = {"allSupported": True, "includeGlobalResourceTypes": True, "resourceTypes": [],
       "exclusionByResourceTypes": {"resourceTypes": []}, "recordingStrategy": {"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"}}


def without(group, key, status):
    """Field omitted while its explicit collection coverage says `status`."""
    trimmed = {k: copy.deepcopy(v) for k, v in group.items() if k != key}
    trimmed["_coverage"] = {key: {"status": status, "error": {"code": "AccessDenied"}}}
    return trimmed


def marked(group, key, status):
    """Field present but its coverage says it was not (fully) collected."""
    return {**copy.deepcopy(group), "_coverage": {key: {"status": status, "error": {"code": "AccessDenied"}}}}


CASES = [
    ("missing_strategy_denied", without(ALL, "recordingStrategy", "denied"), "UNKNOWN"),
    ("missing_strategy_partial", without(ALL, "recordingStrategy", "partial"), "UNKNOWN"),
    ("present_strategy_denied", marked(ALL, "recordingStrategy", "denied"), "UNKNOWN"),
    ("present_strategy_partial", marked(ALL, "recordingStrategy", "partial"), "UNKNOWN"),
    ("missing_strategy_coverage_says_collected", without(ALL, "recordingStrategy", "collected"), "UNKNOWN"),
    ("null_strategy", {**ALL, "recordingStrategy": None}, "UNKNOWN"),
    ("malformed_strategy", {**ALL, "recordingStrategy": "ALL_SUPPORTED_RESOURCE_TYPES"}, "UNKNOWN"),
    ("future_strategy", {**ALL, "recordingStrategy": {"useOnly": "FUTURE"}}, "UNKNOWN"),
    ("legacy_unmarked_all_supported", {"allSupported": True}, "PASS"),
    ("legacy_unmarked_selected_types", {"allSupported": False, "resourceTypes": ["AWS::EC2::Instance"]}, "FAIL"),
    ("all_supported_strategy", copy.deepcopy(ALL), "PASS"),
    ("inclusion_strategy", {**ALL, "allSupported": False, "resourceTypes": ["AWS::EC2::Instance"],
                            "recordingStrategy": {"useOnly": "INCLUSION_BY_RESOURCE_TYPES"}}, "FAIL"),
    ("exclusion_strategy_empty", {**ALL, "allSupported": False,
                                  "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}}, "PASS"),
    ("exclusion_strategy_listed", {**ALL, "allSupported": False, "exclusionByResourceTypes": {"resourceTypes": ["AWS::S3::Bucket"]},
                                   "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}}, "FAIL"),
]


def recorder(group):
    return {"name": "default", "roleARN": "arn:aws:iam::123456789012:role/config", "recordingGroup": group}


def engine_findings(collection):
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "config_recorder", "scope": SCOPE, "service": "config", **collection}],
                             created_at="2026-10-13T00:00:00+00:00")
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=[CID])
    return [finding for finding in report["findings"] if finding["check_id"] == CID]


@pytest.mark.parametrize("group,expected", [case[1:] for case in CASES], ids=[case[0] for case in CASES])
def test_recording_strategy_truth_table_engine_and_memo_index(group, expected):
    item = recorder(group)
    findings = engine_findings({"status": "collected", "items": [copy.deepcopy(item)]})
    assert [finding["status"] for finding in findings] == [expected]
    assert not findings[0]["resource_id"].startswith("inventory:")
    plain = {"collections": {"config_recorder": [{"type": "config_recorder", "scope": SCOPE, "status": "collected", "items": [item]}]}}
    memo = MemoIndex(copy.deepcopy(plain))
    before = copy.deepcopy(item)
    assert CHECK.evaluate(item, plain)[0] == CHECK.evaluate(copy.deepcopy(item), memo)[0] == expected
    assert item == before


@pytest.mark.parametrize("status,expected", [("empty", "EMPTY"), ("denied", "DENIED"), ("partial", "UNKNOWN")])
def test_inventory_level_result_is_not_a_resource_verdict(status, expected):
    findings = engine_findings({"status": status, "items": []})
    assert [(finding["status"], finding["resource_id"]) for finding in findings] == [(expected, "inventory:config_recorder")]


def test_existing_identity_is_preserved():
    matches = [check for check in CHECKS if check.id == CID]
    assert len(matches) == 1
    check = matches[0]
    assert (check.provider, check.category, check.kind, check.severity, check.control, getattr(check, "target", "resource"),
            check.title) == ("aws", "hardening", "config_recorder", "medium", "AU-12", "resource",
                             "AWS Config recorder includes all supported resource types")
