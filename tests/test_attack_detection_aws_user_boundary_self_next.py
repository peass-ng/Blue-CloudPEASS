from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.aws_user_boundary_self_next import normalize_aws_self_user_boundary_delete
from peaso.attack_detection.rules import Rule, detect_aws_events


def record():
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "DeleteUserPermissionsBoundary",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "eventID": "8cad4e6e-90e1-4f15-a775-2135bccb332a",
        "eventTime": "2026-10-18T12:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "userName": "demo", "arn": "arn:aws:iam::123456789012:user/lab/demo"},
        "requestParameters": {"userName": "demo"}, "responseElements": None,
    }


def test_self_boundary_delete_observed_without_net_gain_claim():
    result = normalize_aws_self_user_boundary_delete(record())
    assert result["request.self_user_boundary_delete_observed"] is True
    assert result["target.id"] == "arn:aws:iam::123456789012:user/lab/demo"
    assert not any("privilege" in key or "admin" in key for key in result)


def test_self_boundary_delete_reaches_rule_pipeline():
    rule = Rule(
        id="self-boundary", title="Self boundary removed", level="medium",
        description="Observed removal; review authorization and prior access.",
        technique_id="aws-iam-self-user-boundary-delete", product="aws",
        selection={"event.source": "iam.amazonaws.com",
                   "event.name": "DeleteUserPermissionsBoundary",
                   "event.outcome": "success", "actor.kind": "IAMUser",
                   "request.self_user_boundary_delete_observed": True},
    )
    found = detect_aws_events([record()], [rule])
    assert len(found) == 1
    assert found[0].actor_id == found[0].target_id
    denied = record()
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied], [rule]) == []


@pytest.mark.parametrize("mutation", [
    lambda r: r["requestParameters"].update(userName="other"),
    lambda r: r["userIdentity"].update(type="AssumedRole"),
    lambda r: r["userIdentity"].update(arn="arn:aws:iam::999999999999:user/lab/demo"),
    lambda r: r["userIdentity"].update(userName="other"),
    lambda r: r.update(errorCode="AccessDenied"),
    lambda r: r.update(eventCategory="Data"),
    lambda r: r.update(readOnly=True),
    lambda r: r.update(eventTime="bad"),
    lambda r: r.pop("responseElements"),
    lambda r: r.update(responseElements={"errorCode": "Failed"}),
    lambda r: r.update(requestParameters=[]),
])
def test_fail_closed(mutation):
    bad = deepcopy(record())
    mutation(bad)
    assert normalize_aws_self_user_boundary_delete(bad) is None


def test_malformed_then_valid_is_still_detected():
    results = [normalize_aws_self_user_boundary_delete(value)
               for value in ([], {"eventName": "DeleteUserPermissionsBoundary"}, record())]
    assert results[0] is None and results[1] is None
    assert results[2] is not None
