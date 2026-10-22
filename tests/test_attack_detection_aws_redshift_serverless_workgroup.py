"""Synthetic derivatives of disposable Redshift Serverless network updates."""

from copy import deepcopy

from peaso.attack_detection.aws_redshift_serverless_workgroup import normalize_aws_redshift_serverless_workgroup


FIRST = "sg-0123456789abcdef0"
SECOND = "sg-abcdef01234567890"


def event(request):
    return {"eventSource": "redshift-serverless.amazonaws.com", "eventName": "UpdateWorkgroup",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "999999999999", "awsRegion": "us-east-2",
            "eventTime": "2026-10-22T00:00:00Z", "eventID": "synthetic-update",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::999999999999:user/synthetic"},
            "requestParameters": {"workgroupName": "synthetic-workgroup", **request},
            "responseElements": {"workgroup": {"workgroupName": "synthetic-workgroup",
                                               "publiclyAccessible": False,
                                               "securityGroupIds": [FIRST]}}}


def test_public_request_detected_even_if_response_is_not_yet_updated():
    result = normalize_aws_redshift_serverless_workgroup(event({"publiclyAccessible": True}))
    assert result["request.redshift_serverless_public_access_requested"] is True
    assert "synthetic-workgroup" not in str(result)


def test_security_group_list_replacement_request():
    result = normalize_aws_redshift_serverless_workgroup(event({"securityGroupIds": [SECOND]}))
    assert result["request.redshift_serverless_security_groups_replaced"] is True
    assert SECOND not in str(result)


def test_unrelated_and_failed_updates_do_not_match():
    base = event({"securityGroupIds": [SECOND]})
    for mutate in (lambda x: x.update(errorCode="ValidationException"),
                   lambda x: x.update(readOnly=True),
                   lambda x: x["requestParameters"].update(securityGroupIds=[]),
                   lambda x: x["requestParameters"].update(securityGroupIds=[{"invalid": True}]),
                   lambda x: x["requestParameters"].update(securityGroupIds=[SECOND, SECOND]),
                   lambda x: x["responseElements"]["workgroup"].update(workgroupName="other")):
        changed = deepcopy(base)
        mutate(changed)
        assert normalize_aws_redshift_serverless_workgroup(changed) is None
