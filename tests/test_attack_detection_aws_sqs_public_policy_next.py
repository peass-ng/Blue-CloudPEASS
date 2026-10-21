"""Synthetic derivatives of live batch82 public SQS queue policies."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_sqs_public_policy_batch82_events.json").read_text())
EXPECTED = {"aws-sqs-public-send-grant", "aws-sqs-public-receive-grant"}


def ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if hit.technique_id in EXPECTED}


def policy_event(index, change):
    event = copy.deepcopy(EVENTS[index])
    value = json.loads(event["requestParameters"]["attributes"]["Policy"])
    change(value["Statement"][0])
    event["requestParameters"]["attributes"]["Policy"] = json.dumps(value)
    return event


def test_two_public_grants_match_real_shapes():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 2
    assert {hit.technique_id for hit in hits} == EXPECTED
    assert hits[0].target_id == hits[1].target_id


def test_errors_and_wrong_event_shapes_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDenied"}, {"eventCategory": "Data"},
                       {"readOnly": True}, {"recipientAccountId": "111111111111"}):
            assert not ids({**event, **change})


def test_condition_owner_principal_and_wrong_resource_are_not_public():
    for index in range(2):
        assert not ids(policy_event(index, lambda s: s.update(
            Condition={"IpAddress": {"aws:SourceIp": "192.0.2.0/24"}})))
        assert not ids(policy_event(index, lambda s: s.update(
            Principal={"AWS": "arn:aws:iam::999999999999:root"})))
        assert not ids(policy_event(index, lambda s: s.update(
            Resource="arn:aws:sqs:us-east-1:999999999999:other-queue")))


def test_deny_or_policy_removal_does_not_match():
    for index in range(2):
        event = copy.deepcopy(EVENTS[index])
        event["requestParameters"]["attributes"]["Policy"] = ""
        assert not ids(event)
        event = copy.deepcopy(EVENTS[index])
        document = json.loads(event["requestParameters"]["attributes"]["Policy"])
        document["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "sqs:*",
                                       "Resource": "arn:aws:sqs:us-east-1:999999999999:synthetic-queue"})
        event["requestParameters"]["attributes"]["Policy"] = json.dumps(document)
        assert not ids(event)
