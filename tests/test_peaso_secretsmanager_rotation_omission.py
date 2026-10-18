"""Native Secrets Manager rotation omission stays evidence-bound and fail closed."""

from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "111111111111"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
ARN = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:rotation-fixture-AbCdEf"
IDS = (
    "aws.cb.secretsmanager.rotation_rules_present",
    "aws.cb.secretsmanager.rotation_lambda",
    "aws.cb.secretsmanager.rotated_as_scheduled",
)
REGISTRY = {check.id: check for check in CHECKS}
OMISSION = {"status": "empty", "source_operation": "secretsmanager:DescribeSecret",
            "native_member_present": False}


def secret(*, enabled=False, omission=True):
    item = {"id": ARN, "ARN": ARN, "AccountId": ACCOUNT, "Region": REGION,
            "RotationEnabled": enabled, "CreatedDate": "2025-01-01T00:00:00+00:00",
            "_coverage": {"RotationEnabled": {"status": "collected",
                                           "source_operation": "secretsmanager:DescribeSecret"}}}
    if omission:
        item["_coverage"]["RotationRules"] = copy.deepcopy(OMISSION)
    else:
        item["RotationRules"] = {"AutomaticallyAfterDays": 9999}
        item["RotationLambdaARN"] = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:rotate"
        item["_coverage"]["RotationRules"] = {"status": "collected",
                                              "source_operation": "secretsmanager:DescribeSecret"}
    return item


def statuses(item, *, collection_status="collected", scope=SCOPE):
    collection = {"type": "secret", "scope": scope, "status": collection_status,
                  "items": [copy.deepcopy(item)] if collection_status == "collected" else []}
    if collection_status != "collected":
        collection["error"] = {"code": "read_unavailable"}
    snapshot = make_snapshot("aws", [scope], [collection], created_at="2026-10-18T09:30:52+00:00")
    report = evaluate_snapshot(snapshot, checks=list(IDS))
    return {cid: [finding["status"] for finding in report["findings"]
                  if finding["check_id"] == cid] for cid in IDS}


def assert_all(outcomes, status):
    assert outcomes == {cid: [status] for cid in IDS}


def test_exact_disabled_rotation_omission_is_fail_in_registered_engine():
    assert set(IDS) <= set(REGISTRY)
    assert_all(statuses(secret()), "FAIL")


def test_complete_configured_rotation_remains_pass():
    assert_all(statuses(secret(enabled=True, omission=False)), "PASS")


@pytest.mark.parametrize("change", [
    "missing_marker", "wrong_source", "timeout", "denied", "malformed_marker",
    "contradictory_member", "enabled", "unknown_enabled", "unproven_enabled",
    "wrong_arn", "wrong_account", "wrong_region", "wrong_id", "wrong_scope",
    "malformed_replica",
])
def test_unavailable_or_unbound_omission_stays_unknown(change):
    item = secret()
    scope = SCOPE
    marker = item["_coverage"]["RotationRules"]
    if change == "missing_marker":
        del item["_coverage"]["RotationRules"]
    elif change == "wrong_source":
        marker["source_operation"] = "secretsmanager:ListSecrets"
    elif change in ("timeout", "denied"):
        marker["status"] = change
    elif change == "malformed_marker":
        item["_coverage"]["RotationRules"] = {"status": "empty", "native_member_present": "false"}
    elif change == "contradictory_member":
        item["RotationRules"] = {}
    elif change == "enabled":
        item["RotationEnabled"] = True
    elif change == "unknown_enabled":
        item.pop("RotationEnabled")
    elif change == "unproven_enabled":
        item["_coverage"]["RotationEnabled"]["status"] = "denied"
    elif change == "wrong_arn":
        item["ARN"] = "invalid"
    elif change == "wrong_account":
        item["AccountId"] = "999999999999"
    elif change == "wrong_region":
        item["Region"] = "us-west-2"
    elif change == "wrong_id":
        item["id"] = "not-the-arn"
    elif change == "wrong_scope":
        scope = f"{ACCOUNT}/us-west-2"
    elif change in ("replica", "malformed_replica"):
        item["PrimaryRegion"] = "us-west-2" if change == "replica" else []
    assert_all(statuses(item, scope=scope), "UNKNOWN")


@pytest.mark.parametrize("state", ["denied", "partial", "timeout"])
def test_unavailable_collection_cannot_be_promoted(state):
    assert_all(statuses(secret(), collection_status=state), "DENIED" if state == "denied" else "UNKNOWN")


def test_collected_replica_with_complete_rules_keeps_not_applicable_schedule():
    item = secret(enabled=True, omission=False)
    item["PrimaryRegion"] = "us-west-2"
    outcome = statuses(item)
    assert outcome[IDS[0]] == ["PASS"]
    assert outcome[IDS[1]] == ["PASS"]
    assert outcome[IDS[2]] == ["NOT_APPLICABLE"]


def test_known_replica_schedule_is_inapplicable_without_primary_rotation_rules():
    item = secret()
    item["PrimaryRegion"] = "us-west-2"
    outcome = statuses(item)
    assert outcome[IDS[0]] == ["UNKNOWN"]
    assert outcome[IDS[1]] == ["UNKNOWN"]
    assert outcome[IDS[2]] == ["NOT_APPLICABLE"]
