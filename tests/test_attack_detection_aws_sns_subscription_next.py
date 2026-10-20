"""Synthetic derivatives of live SNS subscription batch81 management events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_sns_subscription_batch81_events.json").read_text())
EXPECTED = {"aws-sns-sqs-subscription-confirmed",
            "aws-sns-subscription-body-filter-scope-set",
            "aws-sns-subscription-filter-policy-set",
            "aws-sns-subscription-raw-delivery-enabled",
            "aws-sns-subscription-list-requested"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def test_five_real_event_shapes_match():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 5
    assert {hit.technique_id for hit in hits} == EXPECTED


def test_errors_wrong_category_and_account_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "InvalidParameter"},
                       {"eventCategory": "Data"},
                       {"managementEvent": False},
                       {"recipientAccountId": "111111111111"}):
            assert not ids({**event, **change})


def test_subscription_must_be_confirmed_for_same_topic():
    event = copy.deepcopy(EVENTS[0])
    event["responseElements"]["subscriptionArn"] = "pending confirmation"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[0])
    event["requestParameters"]["protocol"] = "email"
    assert not ids(event)


def test_filter_requires_nonempty_object_and_body_scope():
    event = copy.deepcopy(EVENTS[2])
    event["requestParameters"]["attributeValue"] = "{}"
    assert not ids(event)
    event = copy.deepcopy(EVENTS[1])
    event["requestParameters"]["attributeValue"] = "MessageAttributes"
    assert not ids(event)


def test_read_and_write_modes_are_distinct():
    for event in EVENTS:
        assert not ids({**event, "readOnly": not event["readOnly"]})
