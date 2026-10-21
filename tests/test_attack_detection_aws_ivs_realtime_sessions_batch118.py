"""Synthetic derivatives of one disposable IVS real-time stage session."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
STAGE = f"arn:aws:ivs:{REGION}:{ACCOUNT}:stage/syntheticstage"
SESSION = "st-1234567890123"
PARTICIPANT = "syntheticpart"
IDS = {
    "aws-ivs-stage-sessions-listed", "aws-ivs-stage-session-read",
    "aws-ivs-participants-listed", "aws-ivs-participant-read",
    "aws-ivs-participant-events-read", "aws-ivs-participant-disconnected",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def event(name, index, request, *, read=False, response=None):
    return {
        "eventSource": "ivs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T15:15:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("ListStageSessions", 1, {"stageArn": STAGE}, read=True),
        event("GetStageSession", 2, {"stageArn": STAGE, "sessionId": SESSION}, read=True),
        event("ListParticipants", 3, {"stageArn": STAGE, "sessionId": SESSION}, read=True),
        event("GetParticipant", 4, {"stageArn": STAGE, "sessionId": SESSION,
                                     "participantId": PARTICIPANT}, read=True),
        event("ListParticipantEvents", 5, {"stageArn": STAGE, "sessionId": SESSION,
                                           "participantId": PARTICIPANT}, read=True),
        event("DisconnectParticipant", 6, {"stageArn": STAGE,
                                           "participantId": PARTICIPANT,
                                           "reason": "synthetic-lab-test"}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_realtime_stage_history_and_disconnect_match_six_rules():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 6


def test_failed_foreign_and_malformed_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["requestParameters"]["stageArn"] = STAGE.replace(ACCOUNT, "111111111111")
    rows[1]["requestParameters"]["sessionId"] = "bad"
    rows[2]["readOnly"] = False
    rows[3]["requestParameters"]["participantId"] = ""
    rows[4]["errorCode"] = "AccessDeniedException"
    rows[5]["requestParameters"]["stageArn"] = STAGE.replace(ACCOUNT, "111111111111")
    assert hits(rows) == []


def test_cloudtrail_read_responses_may_be_redacted():
    rows = sample()[:5]
    for row in rows:
        row["responseElements"] = None
    assert len(hits(rows)) == 5
