"""Synthetic derivatives of batch88 Secrets Manager rotation events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
SECRET = f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:synthetic-secret-abc123"
FUNCTION_A = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:synthetic-rotation-a"
FUNCTION_B = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:synthetic-rotation-b"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-admin/session"
TOKEN = "00000000-0000-4000-8000-000000000001"
PREVIOUS = "00000000-0000-4000-8000-000000000002"
IDS = {
    "aws-secretsmanager-manual-rotation-requested",
    "aws-secretsmanager-rotation-cancelled",
    "aws-secretsmanager-custom-stage-version-planted",
    "aws-secretsmanager-rotation-lambda-swapped",
    "aws-secretsmanager-custom-stage-promoted",
}


def event(name, request, *, when="2026-10-21T00:00:00Z", event_id=None):
    return {
        "eventSource": "secretsmanager.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventTime": when, "eventID": event_id or "synthetic-" + name,
        "userIdentity": {"arn": ACTOR},
        "requestParameters": {"secretId": SECRET, **request},
        "responseElements": {"arn": SECRET, "name": "synthetic-secret"},
    }


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events)
            if hit.technique_id in IDS}


def test_manual_rotation_cancel_and_custom_stage_are_distinct():
    manual = event("RotateSecret", {"rotateImmediately": True})
    cancel = event("CancelRotateSecret", {})
    planted = event("PutSecretValue", {"clientRequestToken": TOKEN, "versionStages": ["CANARY"]})
    assert hits([manual]) == {"aws-secretsmanager-manual-rotation-requested"}
    assert hits([cancel]) == {"aws-secretsmanager-rotation-cancelled"}
    assert hits([planted]) == {"aws-secretsmanager-custom-stage-version-planted"}
    assert not hits([event("RotateSecret", {"rotateImmediately": False})])
    assert not hits([event("PutSecretValue", {"clientRequestToken": TOKEN, "versionStages": ["AWSPENDING"]})])


def test_rotation_function_switch_requires_same_actor_secret_and_window():
    first = event("RotateSecret", {"rotateImmediately": False, "rotationLambdaARN": FUNCTION_A})
    second = event("RotateSecret", {"rotateImmediately": False, "rotationLambdaARN": FUNCTION_B},
                   when="2026-10-21T00:00:03Z", event_id="synthetic-rotation-b")
    assert hits([first, second]) == {"aws-secretsmanager-rotation-lambda-swapped"}
    for mutation in (
        lambda x: x["userIdentity"].update(arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/other/session"),
        lambda x: x["requestParameters"].update(rotationLambdaARN=FUNCTION_A),
        lambda x: x.update(eventTime="2026-10-21T00:20:03Z"),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(recipientAccountId="111111111111"),
    ):
        changed = deepcopy(second)
        mutation(changed)
        assert "aws-secretsmanager-rotation-lambda-swapped" not in hits([first, changed])


def test_custom_version_promotion_requires_matching_version_and_actor():
    plant = event("PutSecretValue", {"clientRequestToken": TOKEN, "versionStages": ["CANARY"]})
    promote = event("UpdateSecretVersionStage", {"versionStage": "AWSCURRENT",
                    "moveToVersionId": TOKEN, "removeFromVersionId": PREVIOUS},
                    when="2026-10-21T00:00:03Z", event_id="synthetic-promote")
    assert hits([plant, promote]) == {
        "aws-secretsmanager-custom-stage-version-planted",
        "aws-secretsmanager-custom-stage-promoted",
    }
    for mutation in (
        lambda x: x["requestParameters"].update(moveToVersionId=PREVIOUS),
        lambda x: x["requestParameters"].update(versionStage="AWSPREVIOUS"),
        lambda x: x["userIdentity"].update(arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/other/session"),
        lambda x: x.update(eventTime="2026-10-21T00:20:03Z"),
        lambda x: x.update(errorCode="ResourceNotFoundException"),
    ):
        changed = deepcopy(promote)
        mutation(changed)
        assert "aws-secretsmanager-custom-stage-promoted" not in hits([plant, changed])


def test_denied_or_foreign_management_events_do_not_match():
    for mutation in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x["responseElements"].update(arn="arn:aws:secretsmanager:us-east-1:999999999999:secret:other"),
    ):
        changed = event("CancelRotateSecret", {})
        mutation(changed)
        assert not hits([changed])
