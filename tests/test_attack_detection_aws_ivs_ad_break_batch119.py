"""Synthetic derivatives of a disposable IVS server-side ad insertion lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
CHANNEL = f"arn:aws:ivs:{REGION}:{ACCOUNT}:channel/syntheticchannel"
AD = f"arn:aws:ivs:{REGION}:{ACCOUNT}:ad-configuration/syntheticads"
PLAYBACK = f"arn:aws:mediatailor:{REGION}:{ACCOUNT}:playbackConfiguration/syntheticplayback"
IDS = {
    "aws-mediatailor-playback-configuration-created",
    "aws-mediatailor-playback-configuration-read",
    "aws-ivs-ad-configuration-created",
    "aws-ivs-ad-configuration-read",
    "aws-ivs-ad-configurations-listed",
    "aws-ivs-channel-ad-configuration-assigned",
    "aws-ivs-ad-break-inserted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 7
    return selected


def event(source, name, index, request, *, read=False, response=None):
    return {
        "eventSource": source, "eventName": name,
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
    mt = "mediatailor.amazonaws.com"
    ivs = "ivs.amazonaws.com"
    return [
        event(mt, "PutPlaybackConfiguration", 1,
              {"Name": "syntheticplayback", "InsertionMode": "PLAYER_SELECT",
               "AdDecisionServerUrl": "https://example.invalid/vast.xml",
               "VideoContentSourceUrl": "https://example.invalid/live/"},
              response={"Name": "syntheticplayback", "PlaybackConfigurationArn": PLAYBACK}),
        event(mt, "GetPlaybackConfiguration", 2, {"Name": "syntheticplayback"}, read=True),
        event(ivs, "CreateAdConfiguration", 3,
              {"name": "syntheticads", "mediaTailorPlaybackConfigurations":
               [{"playbackConfigurationArn": PLAYBACK}]},
              response={"adConfiguration": {"arn": AD, "name": "syntheticads"}}),
        event(ivs, "GetAdConfiguration", 4, {"arn": AD}, read=True),
        event(ivs, "ListAdConfigurations", 5, {"maxResults": 50}, read=True),
        event(ivs, "UpdateChannel", 6, {"arn": CHANNEL, "adConfigurationArn": AD},
              response={"channel": {"arn": CHANNEL, "adConfigurationArn": AD}}),
        event(ivs, "InsertAdBreak", 7, {"channelArn": CHANNEL, "durationSeconds": 5},
              response={"adBreakId": "syntheticbreak"}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_seven_ad_routes_match():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 7


def test_foreign_failed_and_malformed_calls_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["PlaybackConfigurationArn"] = PLAYBACK.replace(ACCOUNT, "111111111111")
    rows[1]["errorCode"] = "NotFoundException"
    rows[2]["requestParameters"]["mediaTailorPlaybackConfigurations"][0]["playbackConfigurationArn"] = PLAYBACK.replace(ACCOUNT, "111111111111")
    rows[3]["requestParameters"]["arn"] = AD.replace(ACCOUNT, "111111111111")
    rows[4]["readOnly"] = False
    rows[5]["responseElements"]["channel"]["adConfigurationArn"] = ""
    rows[6]["responseElements"] = None
    assert hits(rows) == []


def test_read_responses_may_be_redacted_and_ad_action_needs_success():
    rows = sample()
    rows[1]["responseElements"] = None
    rows[3]["responseElements"] = None
    rows[4]["responseElements"] = None
    assert len(hits(rows)) == 7
    rows[6]["errorCode"] = "ConflictException"
    assert "aws-ivs-ad-break-inserted" not in hits(rows)


def test_malformed_ad_url_fails_closed():
    rows = sample()[:1]
    rows[0]["requestParameters"]["AdDecisionServerUrl"] = "https://[broken"
    assert hits(rows) == []
