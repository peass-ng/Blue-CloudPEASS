"""Synthetic derivatives of batch83 SNS topic policy management events."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_sns_public_policy_batch83_events.json").read_text())
EXPECTED = {"aws-sns-public-publish-grant", "aws-sns-public-subscribe-grant"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def changed(index, mutate):
    event = copy.deepcopy(EVENTS[index])
    policy = json.loads(event["requestParameters"]["attributeValue"])
    mutate(policy["Statement"][0])
    event["requestParameters"]["attributeValue"] = json.dumps(policy)
    return event


def test_public_policy_grants_match_live_event_shapes():
    assert ids(EVENTS[0]) == {"aws-sns-public-publish-grant"}
    assert ids(EVENTS[1]) == {"aws-sns-public-subscribe-grant"}


def test_error_wrong_event_and_wrong_target_are_negative():
    for event in EVENTS:
        for altered in ({"errorCode": "AuthorizationError"}, {"eventCategory": "Data"},
                        {"readOnly": True}, {"recipientAccountId": "111111111111"}):
            assert not ids({**event, **altered})
    for index in range(2):
        assert not ids(changed(index, lambda s: s.update(
            Resource="arn:aws:sns:us-east-1:999999999999:other-topic")))


def test_conditions_specific_principal_deny_and_restore_are_negative():
    for index in range(2):
        assert not ids(changed(index, lambda s: s.update(
            Condition={"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}})))
        assert not ids(changed(index, lambda s: s.update(
            Principal={"AWS": "arn:aws:iam::999999999999:root"})))
        event = copy.deepcopy(EVENTS[index])
        policy = json.loads(event["requestParameters"]["attributeValue"])
        policy["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "SNS:*",
            "Resource": "arn:aws:sns:us-east-1:999999999999:synthetic-topic"})
        event["requestParameters"]["attributeValue"] = json.dumps(policy)
        assert not ids(event)
        event["requestParameters"]["attributeValue"] = json.dumps({"Version": "2012-10-17", "Statement": []})
        assert not ids(event)
