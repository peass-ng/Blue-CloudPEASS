"""Synthetic derivatives for five IAM credential-removal routes."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
ROUTES = [
    ("DeleteLoginProfile", {"userName": "synthetic-user"}, "synthetic-user"),
    ("DeleteServiceSpecificCredential", {"userName": "synthetic-user",
       "serviceSpecificCredentialId": "ACCAABCDEFGHIJKLMNOP"}, "synthetic-user"),
    ("RemoveRoleFromInstanceProfile", {"instanceProfileName": "synthetic-profile",
       "roleName": "synthetic-role"}, "synthetic-profile"),
    ("DeleteInstanceProfile", {"instanceProfileName": "synthetic-profile"}, "synthetic-profile"),
    ("DeleteServerCertificate", {"serverCertificateName": "synthetic-cert"}, "synthetic-cert"),
]


@pytest.mark.parametrize("action,params,target", ROUTES)
def test_credential_removal_requires_accepted_named_target(action, params, target):
    event = {"eventSource": "iam.amazonaws.com", "eventName": action,
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
             "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
             "eventID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
             "eventTime": "2026-01-01T00:00:00Z", "requestParameters": params}
    rule = Rule(id="synthetic-" + action, title="Synthetic IAM removal",
                description="Synthetic", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "iam.amazonaws.com",
                    "event.name": action, "event.outcome": "success",
                    "request.iam_credential_deletion_observed": True})
    result = detect_aws_events([event], [rule])
    assert len(result) == 1 and result[0].target_id == target
    for change in ({"errorCode": "NoSuchEntityException"}, {"readOnly": True},
                   {"eventCategory": "Data"}, {"awsRegion": "eu-west-1"},
                   {"recipientAccountId": "111111111111"}):
        bad = deepcopy(event); bad.update(change)
        assert detect_aws_events([bad], [rule]) == []
    bad = deepcopy(event); bad["requestParameters"] = {}
    assert detect_aws_events([bad], [rule]) == []
