"""Normalize SNS subscription and message-body filtering setup events."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_TOPIC = re.compile(r"[A-Za-z0-9_-]{1,256}(?:\.fifo)?\Z")
_SUB_SUFFIX = re.compile(r"[a-f0-9-]{20,50}\Z")
_QUEUE = re.compile(r"[A-Za-z0-9_-]{1,80}(?:\.fifo)?\Z")
_NAMES = {"Subscribe", "SetSubscriptionAttributes", "ListSubscriptionsByTopic"}


def _filter_object(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return False
    return isinstance(parsed, dict) and bool(parsed)


def normalize_aws_sns_subscription(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "sns.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "ListSubscriptionsByTopic")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or response is not None and not isinstance(response, Mapping)):
        return None
    if name == "SetSubscriptionAttributes":
        target = request.get("subscriptionArn")
        if not isinstance(target, str):
            return None
        topic, sep, suffix = target.rpartition(":")
        if not sep or not _SUB_SUFFIX.fullmatch(suffix):
            return None
    else:
        topic = request.get("topicArn")
        target = topic
    prefix = f"arn:aws:sns:{region}:{account}:"
    if (not isinstance(topic, str) or not topic.startswith(prefix)
            or not _TOPIC.fullmatch(topic[len(prefix):])):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    sqs_confirmed = False
    if name == "Subscribe":
        endpoint = request.get("endpoint")
        sqs_confirmed = bool(not failed and request.get("protocol") == "sqs"
                             and isinstance(endpoint, str)
                             and re.fullmatch(r"arn:aws:sqs:" + re.escape(region)
                                              + r":[0-9]{12}:[A-Za-z0-9_.-]{1,80}", endpoint)
                             and isinstance(response, Mapping)
                             and isinstance(response.get("subscriptionArn"), str)
                             and response["subscriptionArn"].startswith(topic + ":")
                             and _SUB_SUFFIX.fullmatch(response["subscriptionArn"][len(topic)+1:]))
        if sqs_confirmed:
            target = response["subscriptionArn"]
    attr, value = request.get("attributeName"), request.get("attributeValue")
    return {
        "cloud.provider": "aws", "event.source": record["eventSource"],
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": actor.get("arn"), "target.id": target,
        "request.sns_sqs_subscription_confirmed": sqs_confirmed,
        "request.sns_body_filter_scope_set": not failed and name == "SetSubscriptionAttributes"
            and attr == "FilterPolicyScope" and value == "MessageBody",
        "request.sns_filter_policy_set": not failed and name == "SetSubscriptionAttributes"
            and attr == "FilterPolicy" and _filter_object(value),
        "request.sns_raw_delivery_enabled": not failed and name == "SetSubscriptionAttributes"
            and attr == "RawMessageDelivery" and value == "true",
        "request.sns_subscription_list_requested": not failed and name == "ListSubscriptionsByTopic",
    }
