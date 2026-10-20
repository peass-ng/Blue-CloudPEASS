"""S3 template notification evidence and cleanup should differ."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="template-notify", title="Template notification", level="medium", description="notify",
    technique_id="aws-s3-cfn-template-bucket-lambda-notification", product="aws",
    selection={"event.source": "s3.amazonaws.com", "event.name": "PutBucketNotification",
               "event.outcome": "success",
               "request.s3_template_bucket_object_created_lambda_notification": True},
)


def test_template_lambda_notification_and_clear() -> None:
    event = {
        "eventSource": "s3.amazonaws.com", "eventName": "PutBucketNotification",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False, "eventID": "synthetic",
        "recipientAccountId": "222233334444",
        "requestParameters": {
            "bucketName": "cf-templates-synthetic-test",
            "NotificationConfiguration": {"CloudFunctionConfiguration": {
                "CloudFunction": "arn:aws:lambda:us-east-1:222233334444:function:synthetic",
                "Event": "s3:ObjectCreated:*"}}},
    }
    assert [d.technique_id for d in detect_aws_events([event], [RULE])] == [RULE.technique_id]
    for variant in ("cleared", "other_bucket", "other_event", "failed", "data_event"):
        item = deepcopy(event)
        if variant == "cleared":
            item["requestParameters"]["NotificationConfiguration"] = {"xmlns": "http://s3.amazonaws.com/doc/2006-03-01/"}
        if variant == "other_bucket":
            item["requestParameters"]["bucketName"] = "unrelated-bucket"
        if variant == "other_event":
            item["requestParameters"]["NotificationConfiguration"]["CloudFunctionConfiguration"]["Event"] = "s3:ObjectRemoved:*"
        if variant == "failed":
            item["errorCode"] = "AccessDenied"
        if variant == "data_event":
            item["eventCategory"] = "Data"
        assert detect_aws_events([item], [RULE]) == [], variant
