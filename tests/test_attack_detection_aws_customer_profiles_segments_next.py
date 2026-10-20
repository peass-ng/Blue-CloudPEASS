"""Synthetic derivatives of five live Customer Profiles segment event shapes."""
from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
SEGMENT = "synthetic_segment"
CASES = [
    ("AssociateStreamForSegments", {"DestinationArn": f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/synthetic",
                                    "DestinationRoleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic"}, "segment_stream_associated"),
    ("PutSegmentSubscription", {"SegmentDefinitionName": SEGMENT,
                                "ScheduleConfiguration": {"Interval": 24, "Unit": "HOURLY"}}, "segment_subscription_put"),
    ("DeleteSegmentSubscription", {"SegmentDefinitionName": SEGMENT}, "segment_subscription_deleted"),
    ("DisassociateStreamForSegments", {}, "segment_stream_disassociated"),
    ("DeleteSegmentDefinition", {"SegmentDefinitionName": SEGMENT}, "segment_definition_deleted"),
]


@pytest.mark.parametrize("name,params,flag", CASES)
def test_customer_profiles_segments(name, params, flag):
    rule = Rule(id="synthetic-" + name, title="Synthetic Customer Profiles segment",
                description="Synthetic dispatch", level="medium", technique_id="synthetic",
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
           "responseElements": {"Status": "STARTING"} if name == "PutSegmentSubscription" else None}
    assert len(detect_aws_events([row], [rule])) == 1
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"readOnly": True},
                   {"managementEvent": False},
                   {"requestParameters": {**row["requestParameters"], "DomainName": "bad/domain"}}):
        denied = deepcopy(row)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
    if name == "PutSegmentSubscription":
        assert detect_aws_events([{**row, "responseElements": {"Status": "FAILED"}}], [rule]) == []
