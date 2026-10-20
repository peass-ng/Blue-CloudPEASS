"""Synthetic derivatives for IAM certificate/key status and deletion signals."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
MFA = f"arn:aws:iam::{ACCOUNT}:mfa/synthetic-mfa"
ROUTES = [
    ("UpdateSSHPublicKey", {"userName": "synthetic-user", "sSHPublicKeyId": "APKAABCDEFGHIJKLMNOP", "status": "Inactive"}, "synthetic-user"),
    ("UpdateSigningCertificate", {"userName": "synthetic-user", "certificateId": "TAKAABCDEFGHIJKLMNOP", "status": "Inactive"}, "synthetic-user"),
    ("UpdateServerCertificate", {"serverCertificateName": "synthetic-server", "newPath": "/synthetic/"}, "synthetic-server"),
    ("DeleteSigningCertificate", {"userName": "synthetic-user", "certificateId": "TAKAABCDEFGHIJKLMNOP"}, "synthetic-user"),
    ("DeleteVirtualMFADevice", {"serialNumber": MFA}, MFA),
]


@pytest.mark.parametrize("action,params,target", ROUTES)
def test_iam_cert_key_control_requires_accepted_named_request(action, params, target):
    event = {"eventSource": "iam.amazonaws.com", "eventName": action,
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
             "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
             "eventID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
             "eventTime": "2026-01-01T00:00:00Z", "requestParameters": params}
    rule = Rule(id="synthetic-" + action, title="Synthetic IAM key control",
                description="Synthetic", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "iam.amazonaws.com",
                    "event.name": action, "event.outcome": "success",
                    "request.iam_cert_key_control_observed": True})
    found = detect_aws_events([event], [rule])
    assert len(found) == 1 and found[0].target_id == target
    for change in ({"errorCode": "NoSuchEntityException"}, {"readOnly": True},
                   {"eventCategory": "Data"}, {"recipientAccountId": "111111111111"},
                   {"awsRegion": "eu-west-1"}):
        bad = deepcopy(event); bad.update(change)
        assert detect_aws_events([bad], [rule]) == []
    bad = deepcopy(event); bad["requestParameters"] = {}
    assert detect_aws_events([bad], [rule]) == []
    if action in {"UpdateSSHPublicKey", "UpdateSigningCertificate"}:
        bad = deepcopy(event); bad["requestParameters"]["status"] = "Active"
        assert detect_aws_events([bad], [rule]) == []
