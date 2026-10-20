"""Synthetic Kinesis data-event derivatives; raw payloads and iterators stay private."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "999999999999"
STREAM = f"arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/synthetic"
CONSUMER = STREAM + "/consumer/synthetic:1234567890"
SENSITIVE = "SYNTHETIC_PRIVATE_PAYLOAD_OR_ITERATOR"
SHARD = "shardId-000000000000"
CASES = [
    ("PutRecord", {"streamARN": STREAM, "partitionKey": "canary", "data": SENSITIVE},
     {"sequenceNumber": "123"}, "request.kinesis_write_request_accepted"),
    ("PutRecords", {"streamARN": STREAM, "records": [{"data": SENSITIVE}]},
     {"failedRecordCount": 0, "records": [{"sequenceNumber": "123"}]},
     "request.kinesis_write_request_accepted"),
    ("GetShardIterator", {"streamARN": STREAM, "shardId": SHARD,
                          "shardIteratorType": "TRIM_HORIZON"}, None,
     "request.kinesis_get_shard_iterator"),
    ("GetRecords", {"shardIterator": SENSITIVE}, None,
     "request.kinesis_get_records"),
    ("SubscribeToShard", {"consumerARN": CONSUMER, "shardId": SHARD}, None,
     "request.kinesis_subscribe_to_shard"),
]


@pytest.mark.parametrize("name,params,response,flag", CASES)
def test_kinesis_data_route(name: str, params: dict, response: dict | None, flag: str) -> None:
    target = CONSUMER if name == "SubscribeToShard" else STREAM
    resource_type = "AWS::Kinesis::StreamConsumer" if name == "SubscribeToShard" else "AWS::Kinesis::Stream"
    record = {"eventSource": "kinesis.amazonaws.com", "eventName": name,
              "eventCategory": "Data", "eventType": "AwsApiCall",
              "managementEvent": False, "readOnly": name not in {"PutRecord", "PutRecords"},
              "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
              "eventID": "11111111-1111-4111-8111-111111111111",
              "eventTime": "2026-10-20T00:00:00Z",
              "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
              "requestParameters": params, "responseElements": response,
              "resources": [{"type": resource_type, "ARN": target}]}
    rule = Rule(id="synthetic-" + name, title="Synthetic Kinesis route",
                description="Synthetic dispatch check", level="low",
                technique_id="synthetic-route", product="aws",
                selection={"event.source": "kinesis.amazonaws.com", "event.name": name,
                           "event.outcome": "success", flag: True})
    found = detect_aws_events([record], [rule])
    assert len(found) == 1 and found[0].target_id == target
    assert SENSITIVE not in str(found[0])
    if name in {"PutRecord", "PutRecords"}:
        # Observed CloudTrail marks both write APIs readOnly=true and omits
        # responseElements. The direct SDK response proved the canary insert.
        observed_shape = {**record, "readOnly": True, "responseElements": None}
        assert len(detect_aws_events([observed_shape], [rule])) == 1
        assert detect_aws_events([{**record, "readOnly": None}], [rule]) == []
    for change in ({"errorCode": "AccessDeniedException"},
                   {"eventCategory": "Management"},
                   {"eventSource": "wrong.amazonaws.com"},
                   {"resources": [{"type": resource_type,
                                   "ARN": target.replace(ACCOUNT, "888888888888")}]}
                   if name == "GetRecords" else {"requestParameters": {**params, "dryRun": True}}):
        denied = deepcopy(record)
        denied.update(change)
        assert detect_aws_events([denied], [rule]) == []
