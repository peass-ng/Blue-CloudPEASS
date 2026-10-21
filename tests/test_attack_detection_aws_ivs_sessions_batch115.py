"""Synthetic derivatives of disposable IVS stream and viewer-control calls."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
CHANNEL = f"arn:aws:ivs:{REGION}:{ACCOUNT}:channel/syntheticchannel"
STAGE = f"arn:aws:ivs:{REGION}:{ACCOUNT}:stage/syntheticstage"
KEY = f"arn:aws:ivs:{REGION}:{ACCOUNT}:stream-key/synthetickey"
IDS = {
    "aws-ivs-stream-key-created", "aws-ivs-stream-keys-listed",
    "aws-ivs-participant-token-issued", "aws-ivs-live-metadata-inserted",
    "aws-ivs-live-stream-stopped", "aws-ivs-stream-sessions-listed",
    "aws-ivs-stream-session-read", "aws-ivs-viewer-revocation-started",
    "aws-ivs-viewers-batch-revoked",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 9
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "ivs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T12:15:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateStreamKey", 1, {"channelArn": CHANNEL},
              {"streamKey": {"arn": KEY, "channelArn": CHANNEL, "value": "***"}}),
        event("ListStreamKeys", 2, {"channelArn": CHANNEL}, read=True),
        event("CreateParticipantToken", 3, {"stageArn": STAGE, "duration": 60,
              "userId": "synthetic-user", "capabilities": ["PUBLISH", "SUBSCRIBE"]},
              {"participantToken": {"token": "***"}}),
        event("PutMetadata", 4, {"channelArn": CHANNEL,
              "metadata": '{"synthetic_lab":true}'}),
        event("StopStream", 5, {"channelArn": CHANNEL}),
        event("ListStreamSessions", 6, {"channelArn": CHANNEL}, read=True),
        event("GetStreamSession", 7, {"channelArn": CHANNEL,
              "streamId": "st-12345678901234567890123"}, read=True),
        event("StartViewerSessionRevocation", 8,
              {"channelArn": CHANNEL, "viewerId": "synthetic-viewer"}, read=True),
        event("BatchStartViewerSessionRevocation", 9,
              {"viewerSessions": [{"channelArn": CHANNEL, "viewerId": "synthetic-a"},
                                  {"channelArn": CHANNEL, "viewerId": "synthetic-b"}]},
              None, read=True),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_ivs_stream_and_control_routes_match_nine_rules():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 9


def test_failed_foreign_and_inconsistent_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["streamKey"]["channelArn"] = CHANNEL.replace(ACCOUNT, "111111111111")
    rows[1]["errorCode"] = "AccessDeniedException"
    rows[2]["requestParameters"]["capabilities"] = ["ADMIN"]
    rows[3]["requestParameters"]["metadata"] = ""
    rows[4]["requestParameters"]["channelArn"] = CHANNEL.replace(ACCOUNT, "111111111111")
    rows[5]["readOnly"] = False
    rows[6]["requestParameters"]["streamId"] = "bad"
    rows[7]["requestParameters"]["viewerId"] = ""
    rows[8]["responseElements"] = {"errors": [{"errorCode": "NotFound"}]}
    assert hits(rows) == []


def test_batch_revocation_requires_one_account_local_channel():
    rows = sample()[8:]
    rows[0]["requestParameters"]["viewerSessions"][1]["channelArn"] = CHANNEL.replace(ACCOUNT, "111111111111")
    assert hits(rows) == []
