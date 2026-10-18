"""Normalize accepted SNS topic and subscription management writes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_TOPIC = re.compile(r"[A-Za-z0-9_-]{1,256}(?:\.fifo)?\Z")
_NAMES = {"RemovePermission", "Unsubscribe", "DeleteTopic"}


def _topic_arn(value: Any, account: str, region: str, partition: str) -> bool:
    parts = _arn(value)
    return bool(parts and parts[1] == partition and parts[2] == "sns"
                and parts[3] == region and parts[4] == account
                and _TOPIC.fullmatch(parts[5]))


def _subscription_arn(value: Any, account: str, region: str, partition: str) -> bool:
    parts = _arn(value)
    if not (parts and parts[1] == partition and parts[2] == "sns"
            and parts[3] == region and parts[4] == account):
        return False
    topic, sep, token = parts[5].rpartition(":")
    if not sep or not _TOPIC.fullmatch(topic):
        return False
    try:
        UUID(token)
    except (TypeError, ValueError, AttributeError):
        return False
    return True


def normalize_aws_sns_topic(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report the accepted operation without inferring prior subscriptions."""
    if (record.get("eventSource") != "sns.amazonaws.com"
            or record.get("eventName") not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or "responseElements" not in record):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or response is not None and not isinstance(response, Mapping)
            or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage"))):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None):
        return None
    name = record["eventName"]
    target = request.get("subscriptionArn") if name == "Unsubscribe" else request.get("topicArn")
    if name == "Unsubscribe":
        if not _subscription_arn(target, account, region, actor[1]):
            return None
    elif not _topic_arn(target, account, region, actor[1]):
        return None
    label = request.get("label")
    if name == "RemovePermission" and (not isinstance(label, str) or not label):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "sns.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": target,
        "request.permission_removed": name == "RemovePermission",
        "request.permission_label": label if name == "RemovePermission" else None,
        "request.unsubscribe_observed": name == "Unsubscribe",
        "request.delete_topic_observed": name == "DeleteTopic",
    }
