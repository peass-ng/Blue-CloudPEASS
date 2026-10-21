"""Synthetic derivatives of Keyspaces optional CloudTrail data events."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
TABLE = f"arn:aws:cassandra:{REGION}:{ACCOUNT}:/keyspace/synthetic_lab/table/synthetic_records"
STREAM = TABLE + "/stream/2026-10-21T12:00:00.000"
IDS = {"aws-keyspaces-" + name for name in (
    "table-select", "table-insert", "table-update", "table-delete",
    "shard-iterator", "records-requested",
)}


def event(name: str) -> dict:
    request = ({"streamArn": STREAM, "shardId": "synthetic-shard", "shardIteratorType": "TRIM_HORIZON"}
               if name == "GetShardIterator" else
               {"shardIterator": "opaque-secret-iterator", "maxResults": 10}
               if name == "GetRecords" else
               {"keyspaceName": "synthetic_lab", "tableName": "synthetic_records"})
    resources = [{"type": "AWS::Cassandra::Table", "ARN": TABLE}]
    if name in {"GetShardIterator", "GetRecords"}:
        resources.insert(0, {"type": "AWS::Cassandra::Stream", "ARN": STREAM})
    return {
        "eventSource": "cassandra.amazonaws.com", "eventName": name,
        "eventCategory": "Data", "eventType": "AwsApiCall",
        "managementEvent": False, "readOnly": name in {"Select", "GetShardIterator", "GetRecords"},
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": request, "resources": resources,
        "responseElements": None,
    }


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def test_six_data_routes_match_and_omit_query_and_iterator_content():
    names = ["Select", "Insert", "Update", "Delete", "GetShardIterator", "GetRecords"]
    hits = detect_aws_events([event(name) for name in names], rules())
    assert len(hits) == 6
    assert Counter(hit.technique_id for hit in hits) == Counter(IDS)
    assert all(hit.target_id == TABLE for hit in hits)
    assert "opaque-secret-iterator" not in str(hits)
    assert "shardIterator" not in str(hits)


def test_denials_wrong_table_and_management_category_do_not_match():
    selected = rules()
    denied = deepcopy(event("Delete")); denied["errorCode"] = "AccessDeniedException"
    wrong = deepcopy(event("Update")); wrong["requestParameters"]["tableName"] = "other"
    foreign = deepcopy(event("GetRecords")); foreign["resources"][0]["ARN"] = STREAM.replace(ACCOUNT, "111111111111")
    management = deepcopy(event("Select")); management["eventCategory"] = "Management"
    contradictory = deepcopy(event("Insert")); contradictory["readOnly"] = True
    assert detect_aws_events([denied, wrong, foreign, management, contradictory], selected) == []


def test_empty_get_records_is_still_only_a_request_signal():
    hit = detect_aws_events([event("GetRecords")], rules())
    assert len(hit) == 1
    assert hit[0].technique_id == "aws-keyspaces-records-requested"
    assert "returned" not in hit[0].evidence
