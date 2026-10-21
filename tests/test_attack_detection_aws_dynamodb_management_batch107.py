"""Synthetic derivatives of owned DynamoDB management CloudTrail events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
TABLE = "synthetic-source"
ARN = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"
BACKUP = ARN + "/backup/synthetic-backup"
STREAM = f"arn:aws:kinesis:{REGION}:{ACCOUNT}:stream/synthetic-stream"
IDS = {
    "aws-dynamodb-pitr-enabled", "aws-dynamodb-backup-created",
    "aws-dynamodb-backup-restored", "aws-dynamodb-backup-deleted",
    "aws-dynamodb-pitr-export-requested", "aws-dynamodb-pitr-restore-requested",
    "aws-dynamodb-kinesis-destination-enabled", "aws-dynamodb-regional-replica-created",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, index, request, *, error=None):
    record = {
        "eventSource": "dynamodb.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"77777777-7777-4777-8777-{index:012d}",
        "eventTime": f"2026-10-21T03:{index:02d}:00Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-role/session"},
        "requestParameters": request, "responseElements": None,
    }
    if error:
        record["errorCode"] = error
    return record


def sample():
    return [
        event("UpdateContinuousBackups", 1, {"tableName": TABLE,
              "pointInTimeRecoverySpecification": {"pointInTimeRecoveryEnabled": True}}),
        event("CreateBackup", 2, {"tableName": TABLE, "backupName": "synthetic-backup"}),
        event("RestoreTableFromBackup", 3, {"targetTableName": "synthetic-backup-clone",
              "backupArn": BACKUP}),
        event("DeleteBackup", 4, {"backupArn": BACKUP}),
        event("ExportTableToPointInTime", 5, {"tableArn": ARN,
              "s3Bucket": "synthetic-private-export", "s3BucketOwner": ACCOUNT,
              "s3Prefix": "synthetic-only"}),
        event("RestoreTableToPointInTime", 6, {"sourceTableName": TABLE,
              "targetTableName": "synthetic-pitr-clone", "useLatestRestorableTime": True}),
        event("EnableKinesisStreamingDestination", 7, {"tableName": TABLE,
              "streamArn": STREAM}),
        event("UpdateTable", 8, {"tableName": TABLE,
              "replicaUpdates": [{"create": {"regionName": "eu-central-1"}}]}),
    ]


def test_eight_management_routes_match_synthetic_event_derivatives():
    hits = detect_aws_events(sample(), rules())
    assert len(hits) == 8
    assert {hit.technique_id for hit in hits} == IDS
    assert "synthetic-only" not in str(hits)


def test_failed_or_malformed_new_requests_are_excluded():
    base = sample()
    variants = []
    for record in base[4:]:
        failed = deepcopy(record)
        failed["errorCode"] = "AccessDeniedException"
        variants.append(failed)
    wrong_account = deepcopy(base[4])
    wrong_account["requestParameters"]["tableArn"] = (
        f"arn:aws:dynamodb:{REGION}:111111111111:table/{TABLE}")
    variants.append(wrong_account)
    no_stream = deepcopy(base[6])
    no_stream["requestParameters"]["streamArn"] = "invalid"
    variants.append(no_stream)
    delete_replica = deepcopy(base[7])
    delete_replica["requestParameters"]["replicaUpdates"] = [
        {"delete": {"regionName": "eu-central-1"}}]
    variants.append(delete_replica)
    same_region = deepcopy(base[7])
    same_region["requestParameters"]["replicaUpdates"][0]["create"]["regionName"] = REGION
    variants.append(same_region)
    assert detect_aws_events(variants, rules()) == []


def test_bad_event_does_not_abort_following_valid_event():
    malformed = deepcopy(sample()[6])
    malformed["eventSource"] = ["dynamodb.amazonaws.com"]
    hits = detect_aws_events([malformed, sample()[6]], rules())
    assert [hit.technique_id for hit in hits] == [
        "aws-dynamodb-kinesis-destination-enabled"]
