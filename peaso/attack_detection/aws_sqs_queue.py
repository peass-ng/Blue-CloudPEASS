"""Normalize completed SQS queue management operations from CloudTrail."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit
from uuid import UUID
from typing import Any

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_QUEUE = re.compile(r"[A-Za-z0-9_-]{1,80}(?:\.fifo)?\Z")
_NAMES = {"RemovePermission", "SetQueueAttributes", "PurgeQueue", "DeleteQueue"}


def _queue_reference(value: Any, account: str, region: str) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.netloc != f"sqs.{region}.amazonaws.com"
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        return None
    parts = parsed.path.strip("/").split("/")
    if (len(parts) != 2 or parts[0] != account or not _QUEUE.fullmatch(parts[1])
            or parsed.path != f"/{account}/{parts[1]}"):
        return None
    return parts[1]


def normalize_aws_sqs_queue(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report an accepted queue write without inferring authorization or data loss."""
    if (record.get("eventSource") != "sqs.amazonaws.com"
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
    queue_name = _queue_reference(request.get("queueUrl"), account, region)
    if queue_name is None:
        return None
    name = record["eventName"]
    attrs = request.get("attributes")
    retention_60 = (name == "SetQueueAttributes" and isinstance(attrs, Mapping)
                    and attrs.get("MessageRetentionPeriod") == "60")
    label = request.get("label")
    permission_removed = name == "RemovePermission" and isinstance(label, str) and bool(label)
    purge = name == "PurgeQueue"
    delete = name == "DeleteQueue"
    if not any((retention_60, permission_removed, purge, delete)):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "sqs.amazonaws.com", "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": f"arn:{actor[1]}:sqs:{region}:{account}:{queue_name}",
        "request.queue_name": queue_name,
        "request.retention_60_seconds": retention_60,
        "request.permission_removed": permission_removed,
        "request.permission_label": label if permission_removed else None,
        "request.purge_queue_observed": purge,
        "request.delete_queue_observed": delete,
    }
