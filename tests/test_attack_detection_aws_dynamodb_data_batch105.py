"""Synthetic derivatives of nine owned DynamoDB CloudTrail data events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
TABLE = "synthetic-table"
ARN = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{TABLE}"
IDS = {
    "aws-dynamodb-get-item-data-read", "aws-dynamodb-batch-get-item-data-read",
    "aws-dynamodb-transact-get-items-data-read", "aws-dynamodb-query-data-read",
    "aws-dynamodb-unfiltered-scan-requested",
    "aws-dynamodb-unfiltered-partiql-select-requested",
    "aws-dynamodb-batch-partiql-select-requested", "aws-dynamodb-old-image-requested",
}
READ_ONLY = {"GetItem", "BatchGetItem", "TransactGetItems", "Query", "Scan"}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, index):
    request = {
        "GetItem": {"tableName": TABLE, "key": {"pk": "synthetic"}},
        "BatchGetItem": {"requestItems": [{"tableName": TABLE, "keys": [{"pk": "synthetic"}]}]},
        "TransactGetItems": {"requestItems": [{"operation": "Get", "tableName": TABLE,
                                               "key": {"pk": "synthetic"}}]},
        "Query": {"tableName": TABLE, "keyConditionExpression": "pk = :pk"},
        "Scan": {"tableName": TABLE, "consistentRead": False},
        "ExecuteStatement": {"statement": f'SELECT * FROM "{TABLE}"'},
        "BatchExecuteStatement": {"requestItems": [{"statement": f'SELECT * FROM "{TABLE}" WHERE pk=?'}]},
        "UpdateItem": {"tableName": TABLE, "returnValue": "ALL_OLD"},
        "PutItem": {"tableName": TABLE, "returnValue": "ALL_OLD"},
    }[name]
    return {
        "eventSource": "dynamodb.amazonaws.com", "eventName": name,
        "eventCategory": "Data", "eventType": "AwsApiCall",
        "managementEvent": False, "readOnly": name in READ_ONLY,
        "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
        "eventID": f"55555555-5555-4555-8555-{index:012d}",
        "eventTime": "2026-10-21T02:45:00Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic/worker"},
        "requestParameters": request, "responseElements": None,
        "resources": [{"type": "AWS::DynamoDB::Table", "ARN": ARN}],
    }


def test_nine_data_events_match_eight_bounded_routes():
    names = ["GetItem", "BatchGetItem", "TransactGetItems", "Query", "Scan",
             "ExecuteStatement", "BatchExecuteStatement", "UpdateItem", "PutItem"]
    hits = detect_aws_events([event(name, i) for i, name in enumerate(names)], rules())
    assert len(hits) == 9
    assert {hit.technique_id for hit in hits} == IDS
    assert sum(hit.technique_id == "aws-dynamodb-old-image-requested" for hit in hits) == 2
    assert "payload" not in str(hits)


def test_errors_and_non_data_events_are_excluded():
    selected = rules()
    for name in ("GetItem", "ExecuteStatement", "UpdateItem"):
        base = event(name, 1)
        denied = deepcopy(base)
        denied["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([denied], selected) == []
        management = deepcopy(base)
        management["eventCategory"] = "Management"
        assert detect_aws_events([management], selected) == []
        contradictory = deepcopy(base)
        contradictory["readOnly"] = not base["readOnly"]
        assert detect_aws_events([contradictory], selected) == []


def test_scope_conditions_exclude_routine_variants_and_writes():
    selected = rules()
    filtered_scan = event("Scan", 1)
    filtered_scan["requestParameters"]["filterExpression"] = "pk = :pk"
    assert detect_aws_events([filtered_scan], selected) == []
    point_select = event("ExecuteStatement", 2)
    point_select["requestParameters"]["statement"] += " WHERE pk = 'synthetic'"
    assert detect_aws_events([point_select], selected) == []
    batch_write = event("BatchExecuteStatement", 3)
    batch_write["requestParameters"]["requestItems"][0]["statement"] = f'UPDATE "{TABLE}" SET payload=1 WHERE pk=?'
    assert detect_aws_events([batch_write], selected) == []
    ordinary_update = event("UpdateItem", 4)
    ordinary_update["requestParameters"]["returnValue"] = "NONE"
    assert detect_aws_events([ordinary_update], selected) == []


def test_foreign_resource_or_malformed_source_cannot_claim_owned_table():
    selected = rules()
    record = event("GetItem", 1)
    record["resources"][0]["ARN"] = f"arn:aws:dynamodb:eu-west-1:111111111111:table/{TABLE}"
    assert detect_aws_events([record], selected) == []
    malformed = event("GetItem", 2)
    malformed["eventSource"] = ["dynamodb.amazonaws.com"]
    hits = detect_aws_events([malformed, event("GetItem", 3)], selected)
    assert [hit.technique_id for hit in hits] == ["aws-dynamodb-get-item-data-read"]
