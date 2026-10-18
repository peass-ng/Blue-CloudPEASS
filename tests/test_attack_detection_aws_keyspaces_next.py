"""Positive and negative evidence for Keyspaces credential creation."""

from __future__ import annotations

from copy import deepcopy
from peaso.attack_detection import Rule, detect_aws_events, load_rules
from peaso.attack_detection.aws_keyspaces_next import normalize_keyspaces_other_user_credential

RULE = Rule(
    id="6839445c-27c1-4c25-9186-02f0b6598837",
    title="Amazon Keyspaces credential created for another IAM user",
    level="medium",
    description="A completed credential creation was observed; review authorization and use separately.",
    technique_id="aws-keyspaces-other-user-service-credential", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "CreateServiceSpecificCredential",
               "event.outcome": "success", "request.service_name": "cassandra.amazonaws.com",
               "request.other_user_keyspaces_credential_created": True},
)


def record() -> dict:
    # The request/response keys also matched one sanitized Cassandra live event.
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "CreateServiceSpecificCredential",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False, "awsRegion": "us-east-1",
        "eventID": "eeb7778f-6e12-48d0-9c60-69155382502d",
        "eventTime": "2026-10-18T17:30:00Z", "recipientAccountId": "947247140022",
        "userIdentity": {"type": "IAMUser", "accountId": "947247140022",
                         "userName": "lab-admin", "arn": "arn:aws:iam::947247140022:user/lab-admin"},
        "requestParameters": {"serviceName": "cassandra.amazonaws.com",
                              "userName": "disposable-user"},
        "responseElements": {"serviceSpecificCredential": {
            "serviceName": "cassandra.amazonaws.com", "userName": "disposable-user",
            "status": "Active", "serviceSpecificCredentialId": "ACCA1234567890EXAMPLE0",
            "serviceUserName": "disposable-user-at-947247140022",
        }},
    }


def test_positive_flat_event_and_pinned_cross_rule() -> None:
    row = record()
    event = normalize_keyspaces_other_user_credential(row)
    assert event is not None
    assert event["target.id"] == "iam-user:947247140022:disposable-user"
    assert event["actor.id"] == row["userIdentity"]["arn"]
    assert event["event.id"] == row["eventID"]
    assert event["event.time"] == row["eventTime"]
    assert all("." in field for field in event)
    assert "serviceSpecificCredentialId" not in str(event)
    assert "serviceUserName" not in str(event)
    matches = detect_aws_events([row], [RULE])
    assert [item.rule_id for item in matches] == [RULE.id]
    published = load_rules(product="aws")
    assert RULE.id in {item.id for item in published}
    assert [item.rule_id for item in detect_aws_events([row], published)] == [RULE.id]


def test_reject_benign_self_credential_and_other_services() -> None:
    rows = []
    self_created = record()
    self_created["requestParameters"]["userName"] = "lab-admin"
    self_created["responseElements"]["serviceSpecificCredential"]["userName"] = "lab-admin"
    rows.append(self_created)
    for service in ("codecommit.amazonaws.com", "bedrock.amazonaws.com", "logs.amazonaws.com"):
        row = record()
        row["requestParameters"]["serviceName"] = service
        row["responseElements"]["serviceSpecificCredential"]["serviceName"] = service
        rows.append(row)
    assert all(normalize_keyspaces_other_user_credential(row) is None for row in rows)


def test_reject_denied_incomplete_or_conflicting_evidence() -> None:
    rows = []
    for edit in ("denied", "response_error", "wrong_source", "wrong_event",
                 "data_event", "read_only", "missing_request", "missing_response",
                 "missing_credential", "wrong_response_service", "wrong_response_user",
                 "inactive", "missing_id", "bad_id", "assumed_role_actor",
                 "foreign_actor_account", "actor_name_mismatch", "missing_actor",
                 "invalid_account", "invalid_event_id", "invalid_time", "missing_region"):
        row = deepcopy(record())
        cred = row["responseElements"]["serviceSpecificCredential"]
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "response_error": row["responseElements"]["errorCode"] = "AccessDenied"
        if edit == "wrong_source": row["eventSource"] = "ec2.amazonaws.com"
        if edit == "wrong_event": row["eventName"] = "ResetServiceSpecificCredential"
        if edit == "data_event": row["eventCategory"] = "Data"
        if edit == "read_only": row["readOnly"] = True
        if edit == "missing_request": row.pop("requestParameters")
        if edit == "missing_response": row.pop("responseElements")
        if edit == "missing_credential": row["responseElements"].pop("serviceSpecificCredential")
        if edit == "wrong_response_service": cred["serviceName"] = "codecommit.amazonaws.com"
        if edit == "wrong_response_user": cred["userName"] = "someone-else"
        if edit == "inactive": cred["status"] = "Inactive"
        if edit == "missing_id": cred.pop("serviceSpecificCredentialId")
        if edit == "bad_id": cred["serviceSpecificCredentialId"] = "bad"
        if edit == "assumed_role_actor": row["userIdentity"]["type"] = "AssumedRole"
        if edit == "foreign_actor_account": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "actor_name_mismatch": row["userIdentity"]["userName"] = "other-admin"
        if edit == "missing_actor": row["userIdentity"].pop("arn")
        if edit == "invalid_account": row["recipientAccountId"] = "invalid"
        if edit == "invalid_event_id": row["eventID"] = "invalid"
        if edit == "invalid_time": row["eventTime"] = "not-a-time"
        if edit == "missing_region": row.pop("awsRegion")
        rows.append(row)
    assert all(normalize_keyspaces_other_user_credential(row) is None for row in rows)
    assert detect_aws_events(rows, [RULE]) == []


def test_malformed_nested_fields_cannot_abort_following_valid_event() -> None:
    bad = []
    for path in (
        ("userIdentity",), ("requestParameters",), ("responseElements",),
        ("responseElements", "serviceSpecificCredential"),
        ("userIdentity", "arn"), ("userIdentity", "userName"),
        ("userIdentity", "accountId"), ("requestParameters", "userName"),
        ("requestParameters", "serviceName"),
        ("responseElements", "serviceSpecificCredential", "serviceSpecificCredentialId"),
        ("responseElements", "serviceSpecificCredential", "status"),
        ("eventID",), ("eventTime",), ("awsRegion",), ("recipientAccountId",),
    ):
        for value in (None, [], {}, 0, True):
            row = deepcopy(record())
            target = row
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            bad.append(row)
    assert all(normalize_keyspaces_other_user_credential(row) is None for row in bad)
    matches = detect_aws_events([*bad, record()], [RULE])
    assert [match.rule_id for match in matches] == [RULE.id]
