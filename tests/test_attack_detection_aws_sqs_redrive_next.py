"""SQS policy and redrive control events require exact accepted parameters."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "222233334444"
SOURCE = f"arn:aws:sqs:us-east-1:{ACCOUNT}:source"
DLQ = f"arn:aws:sqs:us-east-1:{ACCOUNT}:dlq"
DESTINATION = f"arn:aws:sqs:us-east-1:{ACCOUNT}:destination"


def rule(field, name):
    return Rule(id=field, title=field, level="medium", description=field,
                technique_id=field, product="aws", selection={
                    "event.source": "sqs.amazonaws.com", "event.name": name,
                    "event.outcome": "success", field: True})


RULES = tuple(rule(field, name) for field, name in (
    ("request.sqs_redrive_max_one", "SetQueueAttributes"),
    ("request.sqs_redrive_allow_all", "SetQueueAttributes"),
    ("request.sqs_org_wildcard_receive_grant", "SetQueueAttributes"),
    ("request.sqs_custom_redrive_started", "StartMessageMoveTask"),
))


def event(name="SetQueueAttributes", queue="source"):
    return {"eventSource": "sqs.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False, "recipientAccountId": ACCOUNT,
            "requestParameters": {"queueUrl": f"https://sqs.us-east-1.amazonaws.com/{ACCOUNT}/{queue}"},
            "responseElements": None}


def hits(record):
    return [d.technique_id for d in detect_aws_events([record], RULES)]


def test_dlq_route_requires_one_retry_and_same_account_destination():
    item = event()
    item["requestParameters"]["attributes"] = {"RedrivePolicy": json.dumps({
        "deadLetterTargetArn": DLQ, "maxReceiveCount": "1"})}
    assert hits(item) == ["request.sqs_redrive_max_one"]
    for change in ({"maxReceiveCount": "5", "deadLetterTargetArn": DLQ},
                   {"maxReceiveCount": "1", "deadLetterTargetArn": DLQ.replace(ACCOUNT, "111111111111")},
                   {"maxReceiveCount": "1", "deadLetterTargetArn": SOURCE},
                   {"maxReceiveCount": True, "deadLetterTargetArn": DLQ}):
        other = deepcopy(item)
        other["requestParameters"]["attributes"]["RedrivePolicy"] = json.dumps(change)
        assert hits(other) == []
    item["errorCode"] = "AccessDenied"
    assert hits(item) == []
    item.pop("errorCode")
    item["responseElements"] = {"errorCode": "AccessDenied"}
    assert hits(item) == []


def test_explicit_allow_all_and_org_scoped_receive_grant():
    item = event(queue="destination")
    item["requestParameters"]["attributes"] = {"RedriveAllowPolicy": json.dumps({"redrivePermission": "allowAll"})}
    assert hits(item) == ["request.sqs_redrive_allow_all"]
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": ["sqs:ReceiveMessage"], "Resource": DESTINATION,
              "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}}]}
    item["requestParameters"]["attributes"] = {"Policy": json.dumps(policy)}
    assert hits(item) == ["request.sqs_org_wildcard_receive_grant"]
    policy["Statement"][0]["Resource"] = SOURCE
    item["requestParameters"]["attributes"]["Policy"] = json.dumps(policy)
    assert hits(item) == []


def test_move_task_needs_explicit_same_account_destination():
    item = event(name="StartMessageMoveTask")
    item["requestParameters"] = {"sourceArn": DLQ, "destinationArn": DESTINATION}
    assert hits(item) == ["request.sqs_custom_redrive_started"]
    for destination in (DLQ, DESTINATION.replace(ACCOUNT, "111111111111"), None):
        other = deepcopy(item)
        other["requestParameters"]["destinationArn"] = destination
        assert hits(other) == []
    item["errorCode"] = "AccessDenied"
    assert hits(item) == []
