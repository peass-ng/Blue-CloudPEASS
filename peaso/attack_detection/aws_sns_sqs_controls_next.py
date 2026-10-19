"""SNS and SQS grants and destructive control-plane operations."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def _target(source: str, request: Mapping[str, Any], account: str) -> str | None:
    if source == "sns.amazonaws.com":
        value = request.get("subscriptionArn") or request.get("topicArn")
        if (isinstance(value, str) and re.fullmatch(
                rf"arn:aws:sns:[a-z0-9-]+:{re.escape(account)}:[A-Za-z0-9_-]+(?:\.fifo)?(?::[A-Za-z0-9-]+)?", value)):
            return value
    if source == "sqs.amazonaws.com":
        value = request.get("queueUrl")
        if (isinstance(value, str) and re.fullmatch(
                rf"https://sqs\.[a-z0-9-]+\.amazonaws\.com/{re.escape(account)}/[A-Za-z0-9_-]+(?:\.fifo)?", value)):
            return value
    return None


def normalize_aws_sns_sqs_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    names = ({"AddPermission", "RemovePermission", "Unsubscribe", "DeleteTopic"}
             if source == "sns.amazonaws.com" else
             {"AddPermission", "RemovePermission", "SetQueueAttributes", "PurgeQueue", "DeleteQueue"}
             if source == "sqs.amazonaws.com" else set())
    if name not in names:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    account, request = record.get("recipientAccountId"), record.get("requestParameters")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(request, Mapping):
        return None
    target = _target(source, request, account)
    if target is None:
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    label = request.get("label")
    labelled = isinstance(label, str) and bool(label)
    accounts = request.get("aWSAccountId" if source == "sns.amazonaws.com" else "aWSAccountIds")
    actions = request.get("actionName" if source == "sns.amazonaws.com" else "actions")
    other = (isinstance(accounts, list) and all(isinstance(a, str) for a in accounts)
             and any((a == "*" if source == "sns.amazonaws.com" else False)
                     or re.fullmatch(r"\d{12}", a) and a != account for a in accounts))
    attrs = request.get("attributes")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.sns_nonowner_publish_grant": (
            not failed and source == "sns.amazonaws.com" and name == "AddPermission"
            and labelled and other and isinstance(actions, list) and "Publish" in actions
        ),
        "request.sqs_nonowner_receive_grant": (
            not failed and source == "sqs.amazonaws.com" and name == "AddPermission"
            and labelled and other and isinstance(actions, list) and "ReceiveMessage" in actions
        ),
        "request.permission_removed": not failed and name == "RemovePermission" and labelled,
        "request.unsubscribe_observed": not failed and source == "sns.amazonaws.com" and name == "Unsubscribe",
        "request.delete_topic_observed": not failed and source == "sns.amazonaws.com" and name == "DeleteTopic",
        "request.retention_60_seconds": (
            not failed and source == "sqs.amazonaws.com" and name == "SetQueueAttributes"
            and isinstance(attrs, Mapping) and attrs.get("MessageRetentionPeriod") == "60"
        ),
        "request.purge_queue_observed": not failed and source == "sqs.amazonaws.com" and name == "PurgeQueue",
        "request.delete_queue_observed": not failed and source == "sqs.amazonaws.com" and name == "DeleteQueue",
    }
