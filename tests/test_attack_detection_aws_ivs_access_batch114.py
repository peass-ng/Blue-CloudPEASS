"""Synthetic derivatives of disposable IVS control-plane calls; no credentials."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"


def arn(kind, suffix="syntheticid"):
    return f"arn:aws:ivs:{REGION}:{ACCOUNT}:{kind}/{suffix}"


IDS = {
    "aws-ivs-stream-key-read", "aws-ivs-channel-endpoint-read",
    "aws-ivs-stage-endpoint-read", "aws-ivs-ingest-key-read",
    "aws-ivs-playback-authorization-disabled",
    "aws-ivs-realtime-signing-key-imported",
    "aws-ivs-playback-signing-key-imported",
    "aws-ivs-reusable-ingest-created", "aws-ivs-ingest-stage-assigned",
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
        "eventTime": f"2026-10-21T10:15:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("GetStreamKey", 1, {"arn": arn("stream-key")}, read=True),
        event("GetChannel", 2, {"arn": arn("channel")}, read=True),
        event("GetStage", 3, {"arn": arn("stage")}, read=True),
        event("GetIngestConfiguration", 4, {"arn": arn("ingest-configuration")}, read=True),
        event("UpdateChannel", 5, {"arn": arn("channel"), "authorized": False},
              {"channel": {"arn": arn("channel"), "authorized": False}}),
        event("ImportPublicKey", 6, {"name": "synthetic-public-key",
              "publicKeyMaterial": "synthetic-public-material"},
              {"publicKey": {"arn": arn("public-key"), "fingerprint": "synthetic-fingerprint"}}),
        event("ImportPlaybackKeyPair", 7, {"name": "synthetic-playback-key",
              "publicKeyMaterial": "synthetic-public-material"},
              {"keyPair": {"arn": arn("playback-key"), "fingerprint": "synthetic-fingerprint"}}),
        event("CreateIngestConfiguration", 8, {"name": "synthetic-ingest",
              "ingestProtocol": "RTMPS", "stageArn": arn("stage", "stagea")},
              {"ingestConfiguration": {"arn": arn("ingest-configuration"),
                                        "stageArn": arn("stage", "stagea")}}),
        event("UpdateIngestConfiguration", 9, {"arn": arn("ingest-configuration"),
              "stageArn": arn("stage", "stageb")},
              {"ingestConfiguration": {"arn": arn("ingest-configuration"),
                                        "stageArn": arn("stage", "stageb")}}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_synthetic_ivs_routes_match_nine_signals():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 9


def test_failed_foreign_and_inconsistent_ivs_calls_fail_closed():
    rows = sample()
    rows[0]["errorCode"] = "AccessDeniedException"
    rows[1]["requestParameters"]["arn"] = arn("channel").replace(ACCOUNT, "111111111111")
    rows[2]["readOnly"] = False
    rows[3]["eventSource"] = "ivs-realtime.amazonaws.com"
    rows[4]["responseElements"]["channel"]["authorized"] = True
    rows[5]["responseElements"]["publicKey"]["arn"] = arn("public-key").replace(ACCOUNT, "111111111111")
    rows[6]["responseElements"]["keyPair"]["fingerprint"] = ""
    rows[7]["responseElements"]["ingestConfiguration"]["stageArn"] = arn("stage", "other")
    rows[8]["responseElements"]["ingestConfiguration"]["stageArn"] = arn("stage", "other")
    assert hits(rows) == []


def test_response_redaction_does_not_suppress_successful_secret_reads():
    rows = deepcopy(sample()[:4])
    for row in rows:
        row["responseElements"] = None
    assert len(hits(rows)) == 4
