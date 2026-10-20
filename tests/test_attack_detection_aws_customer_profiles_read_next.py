"""Synthetic derivatives for five Customer Profiles read observations."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
PID = "a" * 32
CASES = [
    ("SearchProfiles", {"KeyName": "_ctrContactId", "Values": ["PRIVATE_SYNTHETIC_KEY"]}),
    ("BatchGetProfile", {"ProfileIds": [PID]}),
    ("ListProfileObjects", {"ProfileId": PID, "ObjectTypeName": "synthetic_object"}),
    ("ListProfileHistoryRecords", {"ProfileId": PID}),
    ("ListCalculatedAttributesForProfile", {"ProfileId": PID}),
]


@pytest.mark.parametrize("name,params", CASES)
def test_customer_profiles_read(name: str, params: dict) -> None:
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles read",
                description="Synthetic dispatch", level="low", technique_id="synthetic",
                product="aws", selection={"event.source": "profile.amazonaws.com",
                                          "event.name": name, "event.outcome": "success",
                                          "request.customer_profiles_read_observed": True})
    row = {"eventSource": "profile.amazonaws.com", "eventName": name,
           "eventCategory": "Management", "eventType": "AwsApiCall",
           "managementEvent": True, "readOnly": True,
           "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
           "eventID": "11111111-1111-4111-8111-111111111111",
           "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
           "requestParameters": {"DomainName": "synthetic_domain", **params},
           "responseElements": None}
    found = detect_aws_events([row], [rule])
    assert len(found) == 1 and found[0].target_id
    assert "PRIVATE_SYNTHETIC_KEY" not in str(found[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"readOnly": False},
                   {"requestParameters": {**row["requestParameters"], "DomainName": "bad/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
