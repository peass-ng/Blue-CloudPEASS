"""Synthetic derivative of an owned Cloud Control IAM user lab."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
OTHER_ACCOUNT = str(int(ACCOUNT) - 1)
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-handler"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-caller"
RULE = Rule(
    id="cloudcontrol-passed-role", title="Cloud Control role", level="medium",
    description="synthetic", product="aws",
    technique_id="aws-cloudcontrol-iam-user-with-passed-role",
    selection={
        "event.source": "cloudcontrolapi.amazonaws.com",
        "event.name": "CreateResource", "event.outcome": "success",
        "request.cloudcontrol_iam_user_with_role": True,
    },
)


def event():
    return {
        "eventSource": "cloudcontrolapi.amazonaws.com",
        "eventName": "CreateResource", "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "recipientAccountId": ACCOUNT,
        "eventID": "synthetic-event", "eventTime": "2026-10-23T04:00:00Z",
        "userIdentity": {"arn": ACTOR},
        "requestParameters": {
            "typeName": "AWS::IAM::User", "roleArn": ROLE,
            "desiredState": '{"UserName":"synthetic-target"}',
        },
        "responseElements": {"progressEvent": {"operationStatus": "IN_PROGRESS"}},
    }


def test_passed_role_iam_user_request_and_privacy():
    detections = detect_aws_events([event()], [RULE])
    assert len(detections) == 1
    assert detections[0].technique_id == RULE.technique_id
    assert all(secret not in str(detections) for secret in (ROLE, ACTOR, "synthetic-target"))


def test_denied_unrelated_and_unbounded_request_excluded():
    for edit in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e["requestParameters"].update(typeName="AWS::S3::Bucket"),
        lambda e: e["requestParameters"].pop("roleArn"),
        lambda e: e["requestParameters"].update(roleArn=f"arn:aws:iam::{OTHER_ACCOUNT}:role/other"),
        lambda e: e.update(readOnly=True),
        lambda e: e.update(eventSource="cloudformation.amazonaws.com"),
    ):
        record = deepcopy(event())
        edit(record)
        assert detect_aws_events([record], [RULE]) == []
