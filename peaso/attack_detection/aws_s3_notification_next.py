"""S3 notification changes on CloudFormation template buckets."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_s3_template_notification(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "s3.amazonaws.com" or record.get("eventName") != "PutBucketNotification":
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    bucket = request.get("bucketName")
    if not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        return None
    notification = request.get("NotificationConfiguration")
    config = notification.get("CloudFunctionConfiguration") if isinstance(notification, Mapping) else None
    configs = config if isinstance(config, list) else [config]
    has_created_lambda = False
    for item in configs:
        if not isinstance(item, Mapping):
            continue
        events = item.get("Event")
        events = [events] if isinstance(events, str) else events
        function = item.get("CloudFunction")
        if (isinstance(function, str) and re.fullmatch(
                r"arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+", function)
                and isinstance(events, list) and any(isinstance(event, str)
                and event.startswith("s3:ObjectCreated:") for event in events)):
            has_created_lambda = True
            break
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "s3.amazonaws.com",
        "event.name": "PutBucketNotification", "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId") or identity.get("accountId"),
        "actor.id": identity.get("arn"), "target.id": f"s3://{bucket}",
        "request.s3_template_bucket_object_created_lambda_notification": (
            not failed and bucket.startswith("cf-templates-") and has_created_lambda
        ),
    }
