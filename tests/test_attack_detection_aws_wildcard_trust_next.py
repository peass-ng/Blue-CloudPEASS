"""Live-shaped CloudTrail evidence and benign negatives for wildcard trust."""

from __future__ import annotations

import json
from copy import deepcopy
from urllib.parse import quote

from peaso.attack_detection import Rule
from peaso.attack_detection.aws_wildcard_trust_next import normalize_aws_wildcard_role_trust
from peaso.attack_detection.rules import _detect_events

RULE = Rule(
    id="synthetic-wildcard-trust", title="Unconditional wildcard role trust written", level="high",
    description="The trust policy write succeeded; role assumption and permissions are unknown.",
    technique_id="aws-iam-role-trust-wildcard-principal", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "UpdateAssumeRolePolicy",
               "event.outcome": "success", "request.unconditional_wildcard_trust": True},
)


def _policy() -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
    }]}


def _record() -> dict:
    # Sanitized shape verified against the authorized lab CloudTrail event.
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "UpdateAssumeRolePolicy",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "d2f6eb09-0d2b-41ed-bb6e-6be0a72ac614",
        "eventTime": "2026-10-18T16:57:42Z", "awsRegion": "us-east-1",
        "recipientAccountId": "222233334444",
        "userIdentity": {"type": "IAMUser", "accountId": "222233334444",
                         "arn": "arn:aws:iam::222233334444:user/lab"},
        "requestParameters": {"roleName": "disposable-proof-role",
                              "policyDocument": json.dumps(_policy())},
        "responseElements": None,
    }


def _with_policy(policy: dict) -> dict:
    row = _record()
    row["requestParameters"]["policyDocument"] = json.dumps(policy)
    return row


def test_live_shaped_unconditional_wildcard_matches_without_raw_policy() -> None:
    row = _record()
    event = normalize_aws_wildcard_role_trust(row)
    assert event is not None
    assert event["target.id"] == "iam-role:222233334444:disposable-proof-role"
    assert event["actor.id"] == row["userIdentity"]["arn"]
    assert event["event.id"] == row["eventID"]
    assert event["event.time"] == row["eventTime"]
    assert "policyDocument" not in str(event)
    assert all("." in key for key in event)
    assert len(_detect_events([row], [RULE], normalize_aws_wildcard_role_trust, "aws")) == 1
    row["requestParameters"]["policyDocument"] = quote(json.dumps(_policy()))
    assert normalize_aws_wildcard_role_trust(row) is not None


def test_conditioned_and_narrow_trust_are_benign_negatives() -> None:
    negatives = []
    policy = _policy(); policy["Statement"][0]["Condition"] = {"StringEquals": {"sts:ExternalId": "approved"}}
    negatives.append(_with_policy(policy))
    policy = _policy(); policy["Statement"][0]["Condition"] = {}
    negatives.append(_with_policy(policy))
    policy = _policy(); policy["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::123456789012:root"
    negatives.append(_with_policy(policy))
    policy = _policy(); policy["Statement"].append({"Effect": "Deny", "Principal": {"AWS": "*"},
                                                     "Action": "sts:AssumeRole"})
    negatives.append(_with_policy(policy))
    policy = _policy(); policy["Statement"][0]["Action"] = "sts:TagSession"
    negatives.append(_with_policy(policy))
    assert all(normalize_aws_wildcard_role_trust(row) is None for row in negatives)
    assert _detect_events(negatives, [RULE], normalize_aws_wildcard_role_trust, "aws") == []


def test_denied_or_incomplete_trust_write_fails_closed() -> None:
    rows = []
    for edit in ("denied", "response_error", "wrong_action", "wrong_source",
                 "data_event", "read_only", "missing_response", "missing_role",
                 "missing_policy", "redacted_policy", "invalid_policy", "foreign_actor",
                 "missing_actor", "missing_account", "invalid_id", "invalid_time",
                 "missing_region"):
        row = deepcopy(_record())
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "response_error": row["responseElements"] = {"errorCode": "AccessDenied"}
        if edit == "wrong_action": row["eventName"] = "GetRole"
        if edit == "wrong_source": row["eventSource"] = "ec2.amazonaws.com"
        if edit == "data_event": row["eventCategory"] = "Data"
        if edit == "read_only": row["readOnly"] = True
        if edit == "missing_response": row.pop("responseElements")
        if edit == "missing_role": row["requestParameters"].pop("roleName")
        if edit == "missing_policy": row["requestParameters"].pop("policyDocument")
        if edit == "redacted_policy": row["requestParameters"]["policyDocument"] = "HIDDEN_DUE_TO_SECURITY_REASONS"
        if edit == "invalid_policy": row["requestParameters"]["policyDocument"] = "{bad"
        if edit == "foreign_actor": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_actor": row["userIdentity"].pop("arn")
        if edit == "missing_account": row.pop("recipientAccountId")
        if edit == "invalid_id": row["eventID"] = "not-an-id"
        if edit == "invalid_time": row["eventTime"] = "not-a-time"
        if edit == "missing_region": row.pop("awsRegion")
        rows.append(row)
    assert all(normalize_aws_wildcard_role_trust(row) is None for row in rows)
    assert _detect_events(rows, [RULE], normalize_aws_wildcard_role_trust, "aws") == []
