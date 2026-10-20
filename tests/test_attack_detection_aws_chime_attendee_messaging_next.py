"""Chime SDK signals from a synthetic derivative of disposable live events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_chime_batch64_events.json"
IDS = {
    "1ea4e836-b7af-485c-a6d4-968b3e76ded0",
    "c39a97ee-5309-4fbf-9741-3802cd249a9c",
    "c0322ef4-a598-463f-94c5-6fca351807de",
    "e97949d4-7377-480e-b68e-aa398fe331bd",
    "f0165768-6d4b-416d-86ad-8d9761267e69",
    "049296cb-e91c-40c9-967c-780bb3be464a",
    "2a6c92b7-5af9-40d8-bcb8-a10f747013e2",
    "75c4824c-0f1d-4387-b7f9-d015919b6a33",
    "635fae67-c751-4307-9870-e15839063ee9",
    "a51f1780-1b79-4dc4-bb9e-62581706d4f5",  # Existing admin rule.
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 10
    return rules


def detections(rows):
    return detect_aws_events(rows, selected())


def test_ten_distinct_rules_match_eleven_live_shaped_events():
    rows = events()
    found = detections(rows)
    assert len(rows) == len(found) == 11
    assert {x.rule_id for x in found} == IDS
    assert sum(x.rule_id == "049296cb-e91c-40c9-967c-780bb3be464a" for x in found) == 2
    assert {x["recipientAccountId"] for x in rows} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in rows)
    assert "synthetic message" not in json.dumps([x.evidence for x in found])
    assert "joinToken" not in FIXTURE.read_text()


def test_attendee_reads_require_exact_successful_management_event():
    for change in (
        lambda x: x.update(eventSource="other.amazonaws.com"),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x.update(readOnly=False),
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x["requestParameters"].update(meetingId="wrong"),
    ):
        rows = events()
        change(rows[2])
        assert "c0322ef4-a598-463f-94c5-6fca351807de" not in {d.rule_id for d in detections(rows)}


def test_messaging_requires_bearer_in_same_app_and_actual_success():
    for change in (
        lambda x: x["requestParameters"].update(chimeBearer=x["requestParameters"]["chimeBearer"].replace("33333333", "55555555")),
        lambda x: x["requestParameters"].update(channelArn=x["requestParameters"]["channelArn"].replace("999999999999", "888888888888")),
        lambda x: x.update(errorCode="ForbiddenException"),
        lambda x: x.update(readOnly=True),
    ):
        rows = events()
        change(rows[10])
        assert "635fae67-c751-4307-9870-e15839063ee9" not in {d.rule_id for d in detections(rows)}


def test_created_user_requires_own_app_and_returned_user_arn():
    for change in (
        lambda x: x["responseElements"].update(appInstanceUserArn="arn:aws:chime:us-east-1:888888888888:app-instance/33333333-3333-4333-8333-333333333333/user/other"),
        lambda x: x["responseElements"].update(appInstanceUserArn=x["requestParameters"]["appInstanceArn"] + "/bot/wrong"),
        lambda x: x["requestParameters"].update(appInstanceArn="not-an-app"),
    ):
        rows = events()
        change(rows[5])
        assert sum(d.rule_id == "049296cb-e91c-40c9-967c-780bb3be464a" for d in detections(rows)) == 1


def test_minted_and_sent_claims_require_response_evidence():
    rows = events()
    rows[0]["responseElements"] = None
    rows[1]["responseElements"]["attendees"] = []
    rows[10]["responseElements"]["status"]["value"] = "PENDING"
    found = {d.rule_id for d in detections(rows)}
    assert "1ea4e836-b7af-485c-a6d4-968b3e76ded0" not in found
    assert "c39a97ee-5309-4fbf-9741-3802cd249a9c" not in found
    assert "635fae67-c751-4307-9870-e15839063ee9" not in found
