"""Synthetic derivatives of disposable Redshift Serverless namespace updates."""

from copy import deepcopy

from peaso.attack_detection.aws_redshift_serverless_default_role import (
    normalize_aws_redshift_serverless_default_role,
)


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-empty-redshift-role"


def event():
    return {
        "eventSource": "redshift-serverless.amazonaws.com",
        "eventName": "UpdateNamespace",
        "eventCategory": "Management",
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "readOnly": False,
        "recipientAccountId": ACCOUNT,
        "awsRegion": "us-east-2",
        "eventTime": "2026-10-22T00:00:00Z",
        "eventID": "synthetic-update",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {
            "namespaceName": "synthetic-namespace",
            "iamRoles": [ROLE],
            "defaultIamRoleArn": ROLE,
        },
        "responseElements": {
            "namespace": {
                "namespaceName": "synthetic-namespace",
                "iamRoles": [ROLE],
                "defaultIamRoleArn": ROLE,
            }
        },
    }


def test_accepted_default_role_association_excludes_role_arn():
    result = normalize_aws_redshift_serverless_default_role(event())
    assert result["request.redshift_serverless_default_role_set"] is True
    assert ROLE not in str(result)
    assert "synthetic-namespace" not in str(result)
    assert "__raw_cloudtrail" not in result


def test_rejected_and_mismatched_updates_are_excluded():
    base = event()
    mutations = (
        lambda x: x.update(errorCode="ConflictException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventName="GetNamespace"),
        lambda x: x["requestParameters"].update(namespaceName="other"),
        lambda x: x["requestParameters"].update(iamRoles=[]),
        lambda x: x["requestParameters"].update(defaultIamRoleArn="not-an-arn"),
        lambda x: x["responseElements"]["namespace"].update(defaultIamRoleArn="different"),
    )
    for mutate in mutations:
        record = deepcopy(base)
        mutate(record)
        assert normalize_aws_redshift_serverless_default_role(record) is None
