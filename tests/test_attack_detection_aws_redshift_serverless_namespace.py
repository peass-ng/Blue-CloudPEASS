"""Synthetic derivatives of disposable Redshift Serverless namespace updates."""

from copy import deepcopy

from peaso.attack_detection.aws_redshift_serverless_namespace import normalize_aws_redshift_serverless_namespace


ACCOUNT = "999999999999"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-empty-redshift-role"


def event(request, namespace):
    return {"eventSource": "redshift-serverless.amazonaws.com", "eventName": "UpdateNamespace",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
            "eventTime": "2026-10-22T00:00:00Z", "eventID": "synthetic-namespace-update",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
            "requestParameters": {"namespaceName": "synthetic-namespace", **request},
            "responseElements": {"namespace": {"namespaceName": "synthetic-namespace", **namespace}}}


def test_default_role_change_requires_matching_response():
    record = event({"iamRoles": [ROLE], "defaultIamRoleArn": ROLE},
                   {"iamRoles": [ROLE], "defaultIamRoleArn": ROLE})
    result = normalize_aws_redshift_serverless_namespace(record)
    assert result["request.redshift_serverless_default_role_set"] is True
    assert ROLE not in str(result)
    changed = deepcopy(record)
    changed["responseElements"]["namespace"]["defaultIamRoleArn"] = "different"
    assert normalize_aws_redshift_serverless_namespace(changed) is None


def test_admin_password_reset_does_not_copy_password():
    record = event({"adminUsername": "labadmin", "adminUserPassword": "SYNTHETIC_PASSWORD_NOT_REAL"},
                   {"adminUsername": "labadmin"})
    result = normalize_aws_redshift_serverless_namespace(record)
    assert result["request.redshift_serverless_admin_password_reset"] is True
    assert "SYNTHETIC_PASSWORD_NOT_REAL" not in str(result)
    changed = deepcopy(record)
    changed["requestParameters"].pop("adminUserPassword")
    assert normalize_aws_redshift_serverless_namespace(changed) is None


def test_failed_or_unrelated_update_is_not_reported():
    record = event({"iamRoles": [ROLE], "defaultIamRoleArn": ROLE},
                   {"defaultIamRoleArn": ROLE})
    for mutate in (lambda x: x.update(errorCode="ConflictException"),
                   lambda x: x.update(readOnly=True),
                   lambda x: x.update(eventName="GetNamespace"),
                   lambda x: x["requestParameters"].update(namespaceName="other"),
                   lambda x: x["requestParameters"].update(iamRoles=[])):
        changed = deepcopy(record)
        mutate(changed)
        assert normalize_aws_redshift_serverless_namespace(changed) is None
