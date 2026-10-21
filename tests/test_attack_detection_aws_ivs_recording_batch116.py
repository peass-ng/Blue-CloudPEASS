"""Synthetic derivatives of disposable IVS recording destination lifecycles."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"


def arn(kind):
    return f"arn:aws:ivs:{REGION}:{ACCOUNT}:{kind}/syntheticid"


CHANNEL, STAGE = arn("channel"), arn("stage")
RECORDING, STORAGE = arn("recording-configuration"), arn("storage-configuration")
BUCKET_LOW, BUCKET_RT = "synthetic-low-bucket", "synthetic-rt-bucket"
IDS = {
    "aws-ivs-recording-configuration-created", "aws-ivs-recording-destination-read",
    "aws-ivs-channel-recording-assigned", "aws-ivs-channel-recording-disabled",
    "aws-ivs-storage-configuration-created", "aws-ivs-stage-storage-destination-read",
    "aws-ivs-stage-recording-assigned", "aws-ivs-stage-recording-disabled",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "ivs.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T13:15:{index:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-lab/worker"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateRecordingConfiguration", 1,
              {"name": "synthetic-recording", "destinationConfiguration": {"s3": {"bucketName": BUCKET_LOW}}},
              {"recordingConfiguration": {"arn": RECORDING,
                                          "destinationConfiguration": {"s3": {"bucketName": BUCKET_LOW}}}}),
        event("GetRecordingConfiguration", 2, {"arn": RECORDING}, read=True),
        event("UpdateChannel", 3, {"arn": CHANNEL, "recordingConfigurationArn": RECORDING},
              {"channel": {"arn": CHANNEL, "recordingConfigurationArn": RECORDING}}),
        event("UpdateChannel", 4, {"arn": CHANNEL, "recordingConfigurationArn": ""},
              {"channel": {"arn": CHANNEL, "recordingConfigurationArn": ""}}),
        event("CreateStorageConfiguration", 5,
              {"name": "synthetic-storage", "s3": {"bucketName": BUCKET_RT}},
              {"storageConfiguration": {"arn": STORAGE, "s3": {"bucketName": BUCKET_RT}}}),
        event("GetStorageConfiguration", 6, {"arn": STORAGE}, read=True),
        event("UpdateStage", 7, {"arn": STAGE,
              "autoParticipantRecordingConfiguration": {"storageConfigurationArn": STORAGE}},
              {"stage": {"arn": STAGE,
                         "autoParticipantRecordingConfiguration": {"storageConfigurationArn": STORAGE}}}),
        event("UpdateStage", 8, {"arn": STAGE,
              "autoParticipantRecordingConfiguration": {"storageConfigurationArn": ""}},
              {"stage": {"arn": STAGE,
                         "autoParticipantRecordingConfiguration": {"storageConfigurationArn": ""}}}),
    ]


def hits(rows):
    return [finding.technique_id for finding in detect_aws_events(rows, rules())]


def test_recording_destination_lifecycle_matches_eight_rules():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 8


def test_foreign_buckets_arns_and_failed_responses_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["recordingConfiguration"]["destinationConfiguration"]["s3"]["bucketName"] = "other-bucket"
    rows[1]["requestParameters"]["arn"] = RECORDING.replace(ACCOUNT, "111111111111")
    rows[2]["responseElements"]["channel"]["recordingConfigurationArn"] = ""
    rows[3]["responseElements"]["channel"]["recordingConfigurationArn"] = RECORDING
    rows[4]["responseElements"]["storageConfiguration"]["s3"]["bucketName"] = "other-bucket"
    rows[5]["errorCode"] = "AccessDeniedException"
    rows[6]["responseElements"]["stage"]["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] = ""
    rows[7]["responseElements"]["stage"]["autoParticipantRecordingConfiguration"]["storageConfigurationArn"] = STORAGE
    assert hits(rows) == []
