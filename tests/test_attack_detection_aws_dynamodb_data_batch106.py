"""Synthetic derivatives of owned two-table DynamoDB CloudTrail data events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
TABLE_A = "synthetic-table-a"
TABLE_B = "synthetic-table-b"
ARN_A = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{TABLE_A}"
ARN_B = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{TABLE_B}"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-role/synthetic-session"
IDS = {
    "aws-dynamodb-multi-table-batch-get",
    "aws-dynamodb-classic-denials-then-partiql-select",
    "aws-dynamodb-transaction-old-image-on-failure",
    "aws-dynamodb-batch-write-requested",
    "aws-dynamodb-delete-old-image-requested",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 5
    return selected


def event(name, index, request, *, actor=ACTOR, resources=None, error=None, read_only=None):
    if read_only is None:
        read_only = name in {"GetItem", "Scan", "TransactGetItems", "BatchGetItem"}
    record = {
        "eventSource": "dynamodb.amazonaws.com", "eventName": name,
        "eventCategory": "Data", "eventType": "AwsApiCall",
        "managementEvent": False, "readOnly": read_only,
        "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
        "eventID": f"66666666-6666-4666-8666-{index:012d}",
        "eventTime": f"2026-10-21T03:{index:02d}:00Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT, "arn": actor},
        "requestParameters": request, "responseElements": None,
        "resources": [{"type": "AWS::DynamoDB::Table", "ARN": arn}
                      for arn in (resources if resources is not None else [ARN_A])],
    }
    if error:
        record["errorCode"] = error
    return record


def sample():
    return [
        event("Scan", 1, {"tableName": TABLE_A}, error="AccessDenied"),
        event("TransactGetItems", 2, {"requestItems": [{"operation": "Get", "tableName": TABLE_A}]},
              error="AccessDenied"),
        event("ExecuteStatement", 3, {"statement": f'SELECT * FROM "{TABLE_A}"'}),
        event("BatchGetItem", 4, {"requestItems": [
            {"tableName": TABLE_A, "keys": [{"pk": "synthetic"}]},
            {"tableName": TABLE_B, "keys": [{"pk": "synthetic"}]}]},
              resources=[ARN_A, ARN_B]),
        event("TransactWriteItems", 5, {"requestItems": [{
            "operation": "Update", "tableName": TABLE_A,
            "conditionExpression": "attribute_not_exists(pk)",
            "returnValuesOnConditionCheckFailure": "ALL_OLD",
            "key": {"pk": "synthetic-secret"}}]}, error="TransactionCanceledException"),
        event("BatchWriteItem", 6, {"requestItems": [{
            "operation": "Put", "tableName": TABLE_A,
            "items": [{"pk": "synthetic-secret"}]}]}),
        event("DeleteItem", 7, {"tableName": TABLE_A,
                                "key": {"pk": "synthetic-secret"},
                                "returnValue": "ALL_OLD"}),
    ]


def test_five_routes_match_synthetic_real_shape_derivatives():
    hits = detect_aws_events(sample(), rules())
    assert len(hits) == 5
    assert {hit.technique_id for hit in hits} == IDS
    assert "synthetic-secret" not in str(hits)
    joined = next(hit for hit in hits if hit.technique_id == "aws-dynamodb-classic-denials-then-partiql-select")
    assert len(joined.evidence["correlation"]) == 2


def test_denial_correlation_requires_same_actor_table_and_short_window():
    selected = rules()
    base = sample()
    assert any(hit.technique_id == "aws-dynamodb-classic-denials-then-partiql-select"
               for hit in detect_aws_events(base, selected))
    other_actor = deepcopy(base)
    other_actor[1]["userIdentity"]["arn"] += "-other"
    assert all(hit.technique_id != "aws-dynamodb-classic-denials-then-partiql-select"
               for hit in detect_aws_events(other_actor, selected))
    late = deepcopy(base)
    late[2]["eventTime"] = "2026-10-21T03:30:00Z"
    assert all(hit.technique_id != "aws-dynamodb-classic-denials-then-partiql-select"
               for hit in detect_aws_events(late, selected))
    point_select = deepcopy(base)
    point_select[2]["requestParameters"]["statement"] += " WHERE pk='synthetic'"
    assert all(hit.technique_id != "aws-dynamodb-classic-denials-then-partiql-select"
               for hit in detect_aws_events(point_select, selected))
    one_denial = [record for record in base if record["eventName"] != "Scan"]
    assert all(hit.technique_id != "aws-dynamodb-classic-denials-then-partiql-select"
               for hit in detect_aws_events(one_denial, selected))


def test_request_and_error_guards_exclude_other_operations():
    selected = rules()
    base = sample()
    variants = []
    single_table = deepcopy(base[3])
    single_table["requestParameters"]["requestItems"].pop()
    single_table["resources"].pop()
    variants.append(single_table)
    unrelated_table = deepcopy(base[3])
    unrelated_table["resources"][1]["ARN"] = "arn:aws:dynamodb:eu-west-1:111111111111:table/synthetic-other"
    variants.append(unrelated_table)
    no_old_image = deepcopy(base[4])
    no_old_image["requestParameters"]["requestItems"][0]["returnValuesOnConditionCheckFailure"] = "NONE"
    variants.append(no_old_image)
    success_not_failure = deepcopy(base[4])
    del success_not_failure["errorCode"]
    variants.append(success_not_failure)
    empty_batch = deepcopy(base[5])
    empty_batch["requestParameters"]["requestItems"] = []
    variants.append(empty_batch)
    no_return = deepcopy(base[6])
    no_return["requestParameters"]["returnValue"] = "NONE"
    variants.append(no_return)
    assert detect_aws_events(variants, selected) == []


def test_malformed_source_does_not_abort_following_event():
    malformed = deepcopy(sample()[6])
    malformed["eventSource"] = ["dynamodb.amazonaws.com"]
    hits = detect_aws_events([malformed, sample()[6]], rules())
    assert [hit.technique_id for hit in hits] == ["aws-dynamodb-delete-old-image-requested"]
