"""Explicit external-owner replication needs an accepted configuration."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="external-replication", title="External replication", level="medium", description="replication",
    technique_id="aws-s3-explicit-cross-account-replication", product="aws",
    selection={"event.source": "s3.amazonaws.com", "event.name": "PutBucketReplication",
               "event.outcome": "success", "request.s3_explicit_cross_account_replication": True},
)


def test_explicit_external_owner_and_same_account_negative() -> None:
    event = {
        "eventSource": "s3.amazonaws.com", "eventName": "PutBucketReplication",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False, "recipientAccountId": "947247140022",
        "requestParameters": {"bucketName": "synthetic-source-bucket",
            "ReplicationConfiguration": {"Role": "arn:aws:iam::947247140022:role/synthetic",
                "Rule": {"Status": "Enabled", "Destination": {
                    "Bucket": "arn:aws:s3:::synthetic-destination-bucket",
                    "Account": "111122223333", "AccessControlTranslation": {"Owner": "Destination"}}}}},
    }
    assert [d.technique_id for d in detect_aws_events([event], [RULE])] == [RULE.technique_id]
    for variant in ("same_account", "owner_absent", "disabled", "failed", "data_event"):
        item = deepcopy(event)
        destination = item["requestParameters"]["ReplicationConfiguration"]["Rule"]["Destination"]
        if variant == "same_account":
            destination["Account"] = "947247140022"
        if variant == "owner_absent":
            destination.pop("Account")
        if variant == "disabled":
            item["requestParameters"]["ReplicationConfiguration"]["Rule"]["Status"] = "Disabled"
        if variant == "failed":
            item["errorCode"] = "AccessDenied"
        if variant == "data_event":
            item["eventCategory"] = "Data"
        assert detect_aws_events([item], [RULE]) == [], variant
