"""Synthetic derivatives of five verified Customer Profiles access/change shapes."""
from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
PID = "a" * 32
CASES = [
    ("CreateEventTrigger", {"EventTriggerName": "synthetic_trigger", "ObjectTypeName": "SyntheticType", "EventTriggerConditions": "SYNTHETIC_PRIVATE_CONDITIONS"}, "event_trigger_created", False),
    ("GetUploadJobPath", {"JobId": PID}, "upload_job_path_accessed", True),
    ("PutProfileObject", {"ObjectTypeName": "SyntheticType", "Object": "SYNTHETIC_PRIVATE_BODY"}, "profile_object_ingested", False),
    ("DeleteEventStream", {"EventStreamName": "synthetic_stream"}, "event_stream_deleted", False),
    ("DeleteCalculatedAttributeDefinition", {"CalculatedAttributeName": "synthetic_count"}, "calculated_attribute_deleted", False),
]


@pytest.mark.parametrize("name,params,flag,read_only", CASES)
def test_customer_profiles_paths(name, params, flag, read_only):
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles path",
                description="Synthetic dispatch", level="medium", technique_id="synthetic",
                product="aws", selection={"event.source": "profile.amazonaws.com",
                                          "event.name": name, "event.outcome": "success",
                                          "request.customer_profiles_" + flag: True})
    row = {"eventSource": "profile.amazonaws.com", "eventName": name,
           "eventCategory": "Management", "eventType": "AwsApiCall",
           "managementEvent": True, "readOnly": read_only,
           "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
           "eventID": "11111111-1111-4111-8111-111111111111",
           "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
           "requestParameters": {"DomainName": "synthetic_domain", **params},
           "responseElements": None}
    hits = detect_aws_events([row], [rule])
    assert len(hits) == 1 and hits[0].target_id
    for secret in ("SYNTHETIC_PRIVATE_CONDITIONS", "SYNTHETIC_PRIVATE_BODY"):
        assert secret not in str(hits[0])
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"readOnly": not read_only},
                   {"managementEvent": False},
                   {"requestParameters": {**row["requestParameters"], "DomainName": "bad/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
