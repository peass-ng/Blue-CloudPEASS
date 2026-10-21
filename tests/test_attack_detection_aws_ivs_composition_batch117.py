"""Synthetic derivatives of a disposable IVS composition lifecycle."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"


def arn(kind):
    return f"arn:aws:ivs:{REGION}:{ACCOUNT}:{kind}/syntheticid"


STAGE, CHANNEL = arn("stage"), arn("channel")
ENCODER, COMPOSITION = arn("encoder-configuration"), arn("composition")
IDS = {
    "aws-ivs-encoder-configuration-created",
    "aws-ivs-composition-to-channel-started",
    "aws-ivs-composition-stopped",
    "aws-ivs-composition-read",
    "aws-ivs-compositions-listed",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 5
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "ivs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T14:15:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateEncoderConfiguration", 1,
              {"name": "synthetic-encoder", "video": {"width": 1280, "height": 720,
                                                     "bitrate": 2000000, "framerate": 30}},
              {"encoderConfiguration": {"arn": ENCODER}}),
        event("StartComposition", 2, {"stageArn": STAGE,
              "destinations": [{"channel": {"channelArn": CHANNEL,
                                             "encoderConfigurationArn": ENCODER}}]},
              {"composition": {"arn": COMPOSITION, "stageArn": STAGE,
                               "destinations": [{"configuration": {"channel": {
                                   "channelArn": CHANNEL, "encoderConfigurationArn": ENCODER}}}]}}),
        event("GetComposition", 3, {"arn": COMPOSITION}, read=True),
        event("ListCompositions", 4, {"filterByStageArn": STAGE, "maxResults": 50}, read=True),
        event("StopComposition", 5, {"arn": COMPOSITION}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_composition_lifecycle_matches_five_signals():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 5


def test_foreign_destinations_failed_and_inconsistent_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["encoderConfiguration"]["arn"] = ENCODER.replace(ACCOUNT, "111111111111")
    rows[1]["responseElements"]["composition"]["destinations"][0]["configuration"]["channel"]["channelArn"] = CHANNEL.replace(ACCOUNT, "111111111111")
    rows[2]["requestParameters"]["arn"] = COMPOSITION.replace(ACCOUNT, "111111111111")
    rows[3]["readOnly"] = False
    rows[4]["errorCode"] = "ConflictException"
    assert hits(rows) == []


def test_unfiltered_composition_list_is_detected_at_account_scope():
    row = event("ListCompositions", 1, {"maxResults": 50}, read=True)
    assert hits([row]) == ["aws-ivs-compositions-listed"]
