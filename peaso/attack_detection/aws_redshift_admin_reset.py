"""Normalize accepted Redshift administrator password resets without the secret."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{2,63}\Z")


def normalize_aws_redshift_admin_reset(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    variants = {
        ("redshift-serverless.amazonaws.com", "UpdateNamespace"):
            ("adminUserPassword", "namespaceName", "namespace", "AWS::RedshiftServerless::Namespace"),
        ("redshift.amazonaws.com", "ModifyCluster"):
            ("masterUserPassword", "clusterIdentifier", None, "AWS::Redshift::Cluster"),
    }
    variant = variants.get((source, name))
    if (variant is None or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    password_field, name_field, nested_field, resource_type = variant
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(request.get(password_field), str)
            or not request[password_field]):
        return None
    target_name = request.get(name_field)
    details = response.get(nested_field) if nested_field is not None else response
    if (not isinstance(target_name, str) or not _NAME.fullmatch(target_name)
            or not isinstance(details, Mapping) or details.get(name_field) != target_name):
        return None
    event_id, stamp = record.get("eventID"), record.get("eventTime")
    if not isinstance(event_id, str) or not event_id or not isinstance(stamp, str):
        return None
    try:
        if datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    target = "sha256:" + hashlib.sha256(
        f"{account}:{region}:{source}:{target_name}".encode("utf-8")
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "success", "event.id": event_id, "event.time": stamp,
        "account.id": account, "actor.id": actor, "target.id": target,
        "resource.type": resource_type,
        "request.redshift_admin_password_reset": True,
    }
