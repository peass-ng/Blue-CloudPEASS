"""CloudTrail shape and fail-closed checks for observed boundary deletion."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection import Rule
from peaso.attack_detection.aws_role_boundary_next import normalize_aws_role_boundary_delete
from peaso.attack_detection.rules import _detect_events

RULE = Rule(
    id="synthetic-boundary-delete", title="Role boundary deletion observed", level="high",
    description="The API write succeeded; net privilege change is unknown.",
    technique_id="aws-iam-role-boundary-delete", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "DeleteRolePermissionsBoundary",
               "event.outcome": "success", "request.role_boundary_delete_observed": True},
)


def _record() -> dict:
    # Sanitized shape from the authorized lab CloudTrail proof: a management
    # AwsApiCall in us-east-1 with roleName and null responseElements.
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "DeleteRolePermissionsBoundary",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "f74419f8-3944-47aa-8f47-02575c06f580",
        "eventTime": "2026-10-18T16:33:57Z", "awsRegion": "us-east-1",
        "recipientAccountId": "947247140022",
        "userIdentity": {"type": "IAMUser", "accountId": "947247140022",
                         "arn": "arn:aws:iam::947247140022:user/lab"},
        "requestParameters": {"roleName": "disposable-proof-role"},
        "responseElements": None,
    }


def _matches(record: dict) -> list:
    return _detect_events([record], [RULE], normalize_aws_role_boundary_delete, "aws")


def test_live_shaped_boundary_delete_matches_only_observed_write() -> None:
    row = _record()
    event = normalize_aws_role_boundary_delete(row)
    assert event is not None
    assert event["target.id"] == "iam-role:947247140022:disposable-proof-role"
    assert event["account.id"] == "947247140022"
    assert event["actor.id"] == row["userIdentity"]["arn"]
    assert event["event.id"] == row["eventID"]
    assert event["event.time"] == row["eventTime"]
    assert all("." in key for key in event)
    assert len(_matches(row)) == 1


def test_denied_benign_and_incomplete_boundary_events_fail_closed() -> None:
    rows = []
    for edit in ("denied", "response_error", "wrong_action", "wrong_source",
                 "data_event", "read_only", "missing_response", "missing_role",
                 "invalid_role", "foreign_actor", "missing_actor", "missing_account",
                 "invalid_id", "invalid_time", "missing_region"):
        row = deepcopy(_record())
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "response_error": row["responseElements"] = {"errorCode": "AccessDenied"}
        if edit == "wrong_action": row["eventName"] = "PutRolePermissionsBoundary"
        if edit == "wrong_source": row["eventSource"] = "ec2.amazonaws.com"
        if edit == "data_event": row["eventCategory"] = "Data"
        if edit == "read_only": row["readOnly"] = True
        if edit == "missing_response": row.pop("responseElements")
        if edit == "missing_role": row["requestParameters"].pop("roleName")
        if edit == "invalid_role": row["requestParameters"]["roleName"] = "bad role"
        if edit == "foreign_actor": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_actor": row["userIdentity"].pop("arn")
        if edit == "missing_account": row.pop("recipientAccountId")
        if edit == "invalid_id": row["eventID"] = "not-an-id"
        if edit == "invalid_time": row["eventTime"] = "not-a-time"
        if edit == "missing_region": row.pop("awsRegion")
        rows.append(row)
    assert all(normalize_aws_role_boundary_delete(row) is None for row in rows)
    assert _detect_events(rows, [RULE], normalize_aws_role_boundary_delete, "aws") == []
