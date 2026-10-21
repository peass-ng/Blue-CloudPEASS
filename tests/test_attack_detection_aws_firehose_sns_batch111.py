"""Synthetic derivatives of disposable Firehose and SNS CloudTrail routes."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
STREAM = "synthetic-firehose"
STREAM_ARN = f"arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/{STREAM}"
BUCKET_A = "arn:aws:s3:::synthetic-firehose-a"
BUCKET_B = "arn:aws:s3:::synthetic-firehose-b"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:synthetic-topic"
SUBSCRIPTION = TOPIC + ":11111111-1111-4111-8111-111111111111"
ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/synthetic-sns-a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/synthetic-sns-b"
IDS = {
    "aws-firehose-delivery-topology-read",
    "aws-firehose-direct-record-ingested",
    "aws-firehose-record-batch-write-accepted",
    "aws-firehose-s3-destination-update-requested",
    "aws-firehose-s3-destination-bucket-changed",
    "aws-firehose-delivery-stream-deleted",
    "aws-sns-firehose-subscription-confirmed",
    "aws-sns-firehose-subscription-role-configured",
    "aws-sns-firehose-subscription-role-rebound",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 9
    return selected


def event(source, name, second, request, *, data=False, read=False,
          response=None, error=None):
    record = {
        "eventSource": source, "eventName": name,
        "eventCategory": "Data" if data else "Management",
        "eventType": "AwsApiCall", "managementEvent": not data,
        "readOnly": read, "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"66666666-6666-4666-8666-{second:012d}",
        "eventTime": f"2026-10-21T08:10:{second:02d}Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"},
        "requestParameters": request, "responseElements": response,
    }
    if data:
        record["resources"] = [{"type": "AWS::KinesisFirehose::DeliveryStream",
                                "ARN": STREAM_ARN}]
    if error:
        record["errorCode"] = error
    return record


def firehose(name, second, request=None, **kwargs):
    return event("firehose.amazonaws.com", name, second,
                 request or {"deliveryStreamName": STREAM}, **kwargs)


def sns(name, second, request, **kwargs):
    return event("sns.amazonaws.com", name, second, request, **kwargs)


def sample():
    return [
        firehose("CreateDeliveryStream", 1, {"deliveryStreamName": STREAM,
            "extendedS3DestinationConfiguration": {"bucketARN": BUCKET_A}}),
        firehose("DescribeDeliveryStream", 3, read=True),
        firehose("PutRecord", 5, data=True, read=True),
        firehose("PutRecordBatch", 7, data=True, read=True,
                 response={"failedPutCount": 0}),
        firehose("UpdateDestination", 9, {"deliveryStreamName": STREAM,
            "currentDeliveryStreamVersionId": "1", "destinationId": "destinationId-000000000001",
            "extendedS3DestinationUpdate": {"bucketARN": BUCKET_B}}),
        sns("Subscribe", 11, {"topicArn": TOPIC, "protocol": "firehose",
            "endpoint": STREAM_ARN, "attributes": {"SubscriptionRoleArn": ROLE_A}},
            response={"subscriptionArn": SUBSCRIPTION}),
        sns("SetSubscriptionAttributes", 13, {
            "subscriptionArn": SUBSCRIPTION, "attributeName": "SubscriptionRoleArn",
            "attributeValue": ROLE_B}),
        firehose("DeleteDeliveryStream", 15),
    ]


def test_nine_signals_match_ordered_accepted_events():
    hits = detect_aws_events(sample(), rules())
    assert len(hits) == 9
    assert {hit.technique_id for hit in hits} == IDS
    assert sum(bool(hit.evidence.get("correlation")) for hit in hits) == 2
    assert all(BUCKET_A not in str(hit) and BUCKET_B not in str(hit)
               and ROLE_A not in str(hit) and ROLE_B not in str(hit)
               for hit in hits)


def test_data_events_need_exact_resource_and_full_batch_success():
    rows = sample()
    wrong_resource = deepcopy(rows[2])
    wrong_resource["resources"][0]["ARN"] = (
        f"arn:aws:firehose:{REGION}:111111111111:deliverystream/{STREAM}")
    failed_batch = deepcopy(rows[3])
    failed_batch["responseElements"]["failedPutCount"] = 1
    missing_data_category = deepcopy(rows[2])
    missing_data_category["eventCategory"] = "Management"
    malformed_read_only = deepcopy(rows[2])
    malformed_read_only["readOnly"] = "true"
    assert detect_aws_events([wrong_resource, failed_batch, missing_data_category,
                              malformed_read_only], rules()) == []


def test_same_second_and_cross_account_changes_do_not_correlate():
    rows = sample()
    same_second = deepcopy(rows)
    same_second[4]["eventTime"] = same_second[0]["eventTime"]
    same_second[6]["eventTime"] = same_second[5]["eventTime"]
    ids = {hit.technique_id for hit in detect_aws_events(same_second, rules())}
    assert "aws-firehose-s3-destination-bucket-changed" not in ids
    assert "aws-sns-firehose-subscription-role-rebound" not in ids
    foreign = deepcopy(rows)
    foreign[5]["requestParameters"]["endpoint"] = (
        f"arn:aws:firehose:{REGION}:111111111111:deliverystream/{STREAM}")
    ids = {hit.technique_id for hit in detect_aws_events(foreign[5:7], rules())}
    assert "aws-sns-firehose-subscription-confirmed" not in ids
    assert "aws-sns-firehose-subscription-role-rebound" not in ids


def test_failed_update_and_unchanged_bucket_do_not_claim_redirection():
    rows = sample()
    failed = deepcopy(rows)
    failed[4]["errorCode"] = "AccessDeniedException"
    ids = {hit.technique_id for hit in detect_aws_events(failed, rules())}
    assert "aws-firehose-s3-destination-update-requested" not in ids
    assert "aws-firehose-s3-destination-bucket-changed" not in ids
    unchanged = deepcopy(rows)
    unchanged[4]["requestParameters"]["extendedS3DestinationUpdate"]["bucketARN"] = BUCKET_A
    ids = {hit.technique_id for hit in detect_aws_events(unchanged, rules())}
    assert "aws-firehose-s3-destination-update-requested" in ids
    assert "aws-firehose-s3-destination-bucket-changed" not in ids


def test_deleted_stream_clears_prior_destination_and_duplicate_logs_do_not_hide_change():
    rows = sample()
    delete = firehose("DeleteDeliveryStream", 8)
    hits = detect_aws_events([rows[0], delete, rows[4]], rules())
    assert not any(hit.technique_id == "aws-firehose-s3-destination-bucket-changed"
                   for hit in hits)
    duplicated = [rows[0], deepcopy(rows[0]), rows[4]]
    hits = detect_aws_events(duplicated, rules())
    assert sum(hit.technique_id == "aws-firehose-s3-destination-bucket-changed"
               for hit in hits) == 1
