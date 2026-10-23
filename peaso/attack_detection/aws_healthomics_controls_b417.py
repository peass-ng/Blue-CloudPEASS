"""Accepted HealthOmics data-store and run-group control changes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def _time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit only narrow flags, never S3 bucket paths or run-group IDs."""
    name = record.get("eventName")
    if (record.get("eventSource") != "omics.amazonaws.com"
            or name not in {"UpdateSequenceStore", "UpdateRunGroup"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not _nonempty(account) or not _ACCOUNT.fullmatch(account)
            or not _nonempty(region) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService" or not _nonempty(identity.get("arn"))
            or not isinstance(request, Mapping)
            or not _nonempty(record.get("eventID")) or not _time(record.get("eventTime"))):
        return None
    fields: dict[str, bool] = {}
    if name == "UpdateSequenceStore":
        store, response = request.get("sequenceStoreId"), record.get("responseElements")
        if (not _nonempty(store) or not isinstance(response, Mapping)
                or response.get("id") != store):
            return None
        access = request.get("s3AccessConfig")
        if (isinstance(access, Mapping) and access.get("accessLogLocation") == ""
                and not (isinstance(response.get("s3Access"), Mapping)
                         and response["s3Access"].get("accessLogLocation"))):
            fields["request.healthomics_access_logging_disabled"] = True
        fallback = request.get("fallbackLocation")
        if (_nonempty(fallback) and fallback.startswith("s3://")
                and response.get("fallbackLocation") == fallback):
            fields["request.healthomics_fallback_location_set"] = True
        target_material = f"{account}:{region}:sequence:{store}"
    else:
        group = request.get("id")
        if not _nonempty(group):
            return None
        for key in ("maxCpus", "maxRuns", "maxDuration"):
            value = request.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1:
                fields["request.healthomics_run_group_tight_limit_set"] = True
                break
        target_material = f"{account}:{region}:run-group:{group}"
    if not fields:
        return None
    target = "sha256:" + hashlib.sha256(target_material.encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        **fields,
    }
