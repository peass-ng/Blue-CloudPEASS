"""Password-bearing Redshift changes must match their exact successful response."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


def _event(kind: str) -> dict:
    serverless = kind == "serverless"
    name = "synthetic-namespace" if serverless else "synthetic-cluster"
    return {
        "eventSource": "redshift-serverless.amazonaws.com" if serverless else "redshift.amazonaws.com",
        "eventName": "UpdateNamespace" if serverless else "ModifyCluster",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-cloudtrail-event",
        "eventTime": "2026-10-22T19:00:00Z",
        "recipientAccountId": "999999999999", "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": "999999999999",
                         "arn": "arn:aws:iam::999999999999:user/synthetic-operator"},
        "requestParameters": (
            {"namespaceName": name, "adminUsername": "syntheticadmin",
             "adminUserPassword": "HIDDEN_DUE_TO_SECURITY_REASONS"}
            if serverless else
            {"clusterIdentifier": name, "masterUserPassword": "HIDDEN_DUE_TO_SECURITY_REASONS"}
        ),
        "responseElements": (
            {"namespace": {"namespaceName": name, "status": "MODIFYING"}}
            if serverless else {"clusterIdentifier": name, "clusterStatus": "available"}
        ),
    }


def _rule(kind: str) -> Rule:
    serverless = kind == "serverless"
    return Rule(
        id="synthetic-" + kind, title="Admin reset", level="high",
        description="Admin password changed", product="aws",
        technique_id="aws-redshift-admin-password-reset",
        selection={
            "event.source": "redshift-serverless.amazonaws.com" if serverless else "redshift.amazonaws.com",
            "event.name": "UpdateNamespace" if serverless else "ModifyCluster",
            "event.outcome": "success",
            "request.redshift_admin_password_reset": True,
        },
    )


@pytest.mark.parametrize("kind", ["serverless", "cluster"])
def test_password_reset_is_detected_without_exposing_password(kind: str) -> None:
    event = _event(kind)
    detections = detect_aws_events([event], (_rule(kind),))
    assert len(detections) == 1
    assert detections[0].target_id.startswith("sha256:")
    assert "HIDDEN_DUE_TO_SECURITY_REASONS" not in str(detections[0].evidence)
    assert "adminUserPassword" not in str(detections[0].evidence)
    assert "masterUserPassword" not in str(detections[0].evidence)


@pytest.mark.parametrize("kind", ["serverless", "cluster"])
@pytest.mark.parametrize("change", [
    "wrong_source", "wrong_name", "data_event", "readonly", "denied",
    "missing_password", "empty_password", "different_response_target",
    "missing_response", "foreign_account", "invalid_time", "invalid_target",
])
def test_unproven_password_reset_is_rejected(kind: str, change: str) -> None:
    event = deepcopy(_event(kind))
    password_field = "adminUserPassword" if kind == "serverless" else "masterUserPassword"
    name_field = "namespaceName" if kind == "serverless" else "clusterIdentifier"
    response = event["responseElements"]["namespace"] if kind == "serverless" else event["responseElements"]
    if change == "wrong_source":
        event["eventSource"] = "example.amazonaws.com"
    elif change == "wrong_name":
        event["eventName"] = "DescribeCluster"
    elif change == "data_event":
        event["eventCategory"] = "Data"
    elif change == "readonly":
        event["readOnly"] = True
    elif change == "denied":
        event["errorCode"] = "AccessDeniedException"
    elif change == "missing_password":
        event["requestParameters"].pop(password_field)
    elif change == "empty_password":
        event["requestParameters"][password_field] = ""
    elif change == "different_response_target":
        response[name_field] = "different-target"
    elif change == "missing_response":
        event["responseElements"] = None
    elif change == "foreign_account":
        event["recipientAccountId"] = "bad-account"
    elif change == "invalid_time":
        event["eventTime"] = "yesterday"
    elif change == "invalid_target":
        event["requestParameters"][name_field] = "../bad"
    assert not detect_aws_events([event], (_rule(kind),))
