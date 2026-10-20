"""Accepted KMS alias changes and automatic rotation disablement."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_KEY_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_ALIAS = re.compile(r"alias/[A-Za-z0-9/_-]+\Z")


def normalize_aws_kms_alias_rotation(record: Mapping[str, Any]) -> dict[str, Any] | None:
    operation = record.get("eventName")
    if (record.get("eventSource") != "kms.amazonaws.com"
            or operation not in {"UpdateAlias", "DeleteAlias", "DisableKeyRotation"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(region, str):
        return None
    response = record.get("responseElements")
    resources = record.get("resources")
    if not isinstance(resources, list):
        return None
    resource_arns = {r.get("ARN") for r in resources if isinstance(r, Mapping)
                     and r.get("accountId") == account and isinstance(r.get("ARN"), str)}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    alias_remapped = alias_deleted = rotation_disabled = False
    target = None
    if operation in {"UpdateAlias", "DeleteAlias"}:
        alias_name = request.get("aliasName")
        if not isinstance(alias_name, str) or not _ALIAS.fullmatch(alias_name):
            return None
        alias_arn = f"arn:aws:kms:{region}:{account}:{alias_name}"
        if alias_arn not in resource_arns or not isinstance(response, Mapping):
            return None
        target = alias_arn
        key_arn = response.get("keyId")
        if not isinstance(key_arn, str) or key_arn not in resource_arns:
            return None
        prefix = f"arn:aws:kms:{region}:{account}:key/"
        if not key_arn.startswith(prefix) or not _KEY_ID.fullmatch(key_arn[len(prefix):]):
            return None
        if operation == "UpdateAlias":
            requested_key = request.get("targetKeyId")
            same_key = requested_key == key_arn or requested_key == key_arn[len(prefix):]
            alias_remapped = not failed and same_key
        else:
            alias_deleted = not failed
    else:
        requested_key = request.get("keyId")
        prefix = f"arn:aws:kms:{region}:{account}:key/"
        if not isinstance(requested_key, str):
            return None
        key_arn = requested_key if requested_key.startswith(prefix) else prefix + requested_key
        if not _KEY_ID.fullmatch(key_arn[len(prefix):]) or key_arn not in resource_arns:
            return None
        if response is not None:
            if not isinstance(response, Mapping) or response.get("keyId") != key_arn:
                return None
        target = key_arn
        rotation_disabled = not failed
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {"cloud.provider": "aws", "event.source": "kms.amazonaws.com",
            "event.name": operation, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
            "request.kms_alias_remapped": alias_remapped,
            "request.kms_alias_deleted": alias_deleted,
            "request.kms_rotation_disabled": rotation_disabled}
