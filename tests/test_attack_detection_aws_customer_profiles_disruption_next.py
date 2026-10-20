"""Synthetic derivatives of five live Customer Profiles change/delete event shapes."""
from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
PID = "a" * 32
CASES = [
    ("UpdateEventTrigger", {"EventTriggerName": "synthetic_trigger", "EventTriggerConditions": "SYNTHETIC_PRIVATE_CONDITIONS"}, "event_trigger_updated"),
    ("DeleteProfileObject", {"ProfileId": PID, "ObjectTypeName": "SyntheticType", "ProfileObjectUniqueKey": "SYNTHETIC_PRIVATE_KEY"}, "profile_object_deleted"),
    ("DeleteEventTrigger", {"EventTriggerName": "synthetic_trigger"}, "event_trigger_deleted"),
    ("DeleteProfileObjectType", {"ObjectTypeName": "SyntheticType"}, "profile_object_type_deleted"),
    ("DeleteProfile", {"ProfileId": PID}, "profile_deleted"),
]


@pytest.mark.parametrize("name,params,flag", CASES)
def test_customer_profiles_disruption(name, params, flag):
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles change",
                description="Synthetic dispatch", level="high", technique_id="synthetic",
                product="aws", selection={"event.source": "profile.amazonaws.com",
                                          "event.name": name, "event.outcome": "success",
                                          "request.customer_profiles_" + flag: True})
    row = {"eventSource": "profile.amazonaws.com", "eventName": name,
           "eventCategory": "Management", "eventType": "AwsApiCall",
           "managementEvent": True, "readOnly": False,
           "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
           "eventID": "11111111-1111-4111-8111-111111111111",
           "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
           "requestParameters": {"DomainName": "synthetic_domain", **params},
           "responseElements": {"Message": "accepted"}}
    hits = detect_aws_events([row], [rule])
    assert len(hits) == 1 and hits[0].target_id
    assert "SYNTHETIC_PRIVATE_KEY" not in str(hits[0])
    assert "SYNTHETIC_PRIVATE_CONDITIONS" not in str(hits[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"readOnly": True},
                   {"managementEvent": False},
                   {"requestParameters": {**row["requestParameters"], "DomainName": "bad/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
