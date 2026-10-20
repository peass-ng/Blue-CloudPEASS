"""Synthetic derivatives for IAM target-specific deletion signals."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
TARGETS = [
    ("DeleteSSHPublicKey", {"userName": "synthetic-user", "sSHPublicKeyId": "APKAABCDEFGHIJKLMNOP"}, "synthetic-user"),
    ("RemoveUserFromGroup", {"userName": "synthetic-user", "groupName": "synthetic-group"}, "synthetic-user"),
    ("DeleteUser", {"userName": "synthetic-user"}, "synthetic-user"),
    ("DeleteRole", {"roleName": "synthetic-role"}, "synthetic-role"),
    ("DeleteGroup", {"groupName": "synthetic-group"}, "synthetic-group"),
]


@pytest.mark.parametrize("action,params,target", TARGETS)
def test_named_iam_deletion_requires_accepted_owned_target(action, params, target):
    event = {"eventSource": "iam.amazonaws.com", "eventName": action,
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
             "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
             "eventID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
             "eventTime": "2026-01-01T00:00:00Z", "requestParameters": params}
    rule = Rule(id="synthetic-" + action, title="Synthetic IAM deletion",
                description="Synthetic", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "iam.amazonaws.com",
                    "event.name": action, "event.outcome": "success",
                    "request.iam_identity_deletion_observed": True})
    found = detect_aws_events([event], [rule])
    assert len(found) == 1 and found[0].target_id == target
    for change in ({"errorCode": "NoSuchEntity"}, {"readOnly": True},
                   {"awsRegion": "eu-west-1"}, {"eventCategory": "Data"},
                   {"recipientAccountId": "111111111111"}):
        bad = deepcopy(event); bad.update(change)
        assert detect_aws_events([bad], [rule]) == []
    bad = deepcopy(event); bad["requestParameters"] = {}
    assert detect_aws_events([bad], [rule]) == []
