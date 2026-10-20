"""Chime capability and channel-flow signals from synthetic live derivatives."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_batch65_events.json"
IDS = {
    "6a3ab57b-dfac-49e2-9b61-13c0aa8a3412",
    "f03b2c83-a07f-42bc-b61a-e03a68083ab9",
    "0d6f5d90-971d-4777-a568-d5555e5aa824",
    "280ea3e4-81dd-4bb8-9aa4-f3205a27b911",
    "07494751-7b54-4e2e-a9df-d3c2af771866",
    "27073075-0baa-4d71-93ba-0a6ee40bbd87",
    "bbd3c85e-451a-4bbc-88d3-c0b2451f43f7",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 7
    return rules


def found(rows):
    return detect_aws_events(rows, selected())


def ids(rows):
    return {x.rule_id for x in found(rows)}


def test_seven_rules_match_ten_live_shaped_signals():
    rows = events()
    detections = found(rows)
    assert len(rows) == 8
    assert len(detections) == 10
    assert {x.rule_id for x in detections} == IDS
    assert sum(x.rule_id == "6a3ab57b-dfac-49e2-9b61-13c0aa8a3412"
               for x in detections) == 3
    assert sum(x.rule_id == "bbd3c85e-451a-4bbc-88d3-c0b2451f43f7"
               for x in detections) == 2
    assert {x["recipientAccountId"] for x in rows} == {"999999999999"}
    assert "joinToken" not in FIXTURE.read_text()
    assert "synthetic message" not in json.dumps([d.evidence for d in detections])


def test_attendee_capability_claim_requires_matching_successful_response():
    for change in (
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x.update(readOnly=True),
        lambda x: x["responseElements"]["attendee"].update(attendeeId="88888888-8888-4888-8888-888888888888"),
        lambda x: x["responseElements"]["attendee"]["capabilities"].update(audio="None"),
        lambda x: x["requestParameters"].update(meetingId="wrong"),
    ):
        rows = events()
        change(rows[0])
        assert "f03b2c83-a07f-42bc-b61a-e03a68083ab9" not in ids(rows)


def test_flow_processor_requires_same_account_lambda_and_returned_flow():
    for change in (
        lambda x: x["requestParameters"]["processors"][0]["configuration"]["lambda"].update(resourceArn="arn:aws:lambda:us-east-1:888888888888:function:other"),
        lambda x: x["requestParameters"]["processors"][0]["configuration"]["lambda"].update(invocationType="SYNC"),
        lambda x: x["responseElements"].update(channelFlowArn=x["responseElements"]["channelFlowArn"].replace("999999999999", "888888888888")),
        lambda x: x.update(errorCode="BadRequestException"),
    ):
        rows = events()
        change(rows[3])
        assert "280ea3e4-81dd-4bb8-9aa4-f3205a27b911" not in ids(rows)


def test_flow_association_requires_same_app_and_valid_bearer():
    for change in (
        lambda x: x["requestParameters"].update(channelFlowArn=x["requestParameters"]["channelFlowArn"].replace("33333333", "55555555")),
        lambda x: x["requestParameters"].update(chimeBearer="arn:aws:chime:us-east-1:888888888888:app-instance/other/user/other"),
        lambda x: x.update(errorCode="ForbiddenException"),
    ):
        rows = events()
        change(rows[5])
        assert "27073075-0baa-4d71-93ba-0a6ee40bbd87" not in ids(rows)


def test_callback_requires_matching_success_without_content_in_alert():
    for change in (
        lambda x: x["responseElements"].update(callbackId="other"),
        lambda x: x["responseElements"].update(channelArn="arn:aws:chime:us-east-1:888888888888:app-instance/other/channel/other"),
        lambda x: x.update(errorCode="BadRequestException"),
    ):
        rows = events()
        change(rows[6])
        assert sum(d.rule_id == "bbd3c85e-451a-4bbc-88d3-c0b2451f43f7"
                   for d in found(rows)) == 1
