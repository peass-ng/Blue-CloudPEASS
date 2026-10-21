"""Synthetic derivatives of live batch84 SNS service grants."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_sns_service_scope_batch84_events.json").read_text())
EXPECTED = {"aws-sqs-sns-unscoped-send-grant", "aws-sqs-sns-account-wide-send-grant",
            "aws-lambda-sns-unscoped-invoke-grant"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def queue_policy(index, change):
    event = copy.deepcopy(EVENTS[index])
    policy = json.loads(event["requestParameters"]["attributes"]["Policy"])
    change(policy["Statement"][0])
    event["requestParameters"]["attributes"]["Policy"] = json.dumps(policy)
    return event


def test_distinguishes_exact_account_wide_and_unscoped_sources():
    assert ids(EVENTS[0]) == set()
    assert ids(EVENTS[1]) == {"aws-sqs-sns-account-wide-send-grant"}
    assert ids(EVENTS[2]) == {"aws-sqs-sns-unscoped-send-grant"}
    assert ids(EVENTS[3]) == {"aws-lambda-sns-unscoped-invoke-grant"}
    assert ids(EVENTS[4]) == set()


def test_failed_writes_and_wrong_event_categories_are_negative():
    for event in EVENTS:
        assert not ids({**event, "errorCode": "AccessDenied"})
        assert not ids({**event, "eventCategory": "Data"})
        assert not ids({**event, "recipientAccountId": "111111111111"})


def test_queue_policy_requires_exact_service_action_resource_and_scope():
    for index in (1, 2):
        assert not ids(queue_policy(index, lambda s: s.update(
            Principal={"Service": "events.amazonaws.com"})))
        assert not ids(queue_policy(index, lambda s: s.update(Action="sqs:ReceiveMessage")))
        assert not ids(queue_policy(index, lambda s: s.update(
            Resource="arn:aws:sqs:us-east-1:999999999999:other-queue")))
    assert not ids(queue_policy(2, lambda s: s.update(
        Condition={"ArnEquals": {"aws:SourceArn":
            "arn:aws:sns:us-east-1:999999999999:synthetic-topic"}})))


def test_lambda_grant_requires_matching_accepted_statement_and_no_source():
    event = copy.deepcopy(EVENTS[3])
    event["responseElements"]["statement"] = "{}"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[3])
    event["requestParameters"]["sourceArn"] = "arn:aws:sns:us-east-1:999999999999:synthetic-topic"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[3])
    statement = json.loads(event["responseElements"]["statement"])
    statement["Condition"] = {"ArnLike": {"AWS:SourceArn":
        "arn:aws:sns:us-east-1:999999999999:synthetic-topic"}}
    event["responseElements"]["statement"] = json.dumps(statement)
    assert not ids(event)
