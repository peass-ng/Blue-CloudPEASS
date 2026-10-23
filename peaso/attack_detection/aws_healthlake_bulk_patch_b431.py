"""Accepted HealthLake bulk patch submissions without FHIR request bodies."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_STORE = re.compile(r"[0-9a-f]{32}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """CloudTrail stores the patch payload as a byte buffer; never expose it."""
    if (record.get("eventSource") != "healthlake.amazonaws.com"
            or record.get("eventName") != "StartFHIRBulkPatchJob"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    response = record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or str(response.get("statusCode")) != "202"
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    store = request.get("datastoreId")
    if not isinstance(store, str) or not _STORE.fullmatch(store):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    target = "sha256:" + hashlib.sha256(":".join((account, region, store)).encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "healthlake.amazonaws.com",
        "event.name": "StartFHIRBulkPatchJob", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthlake_bulk_patch_submitted": True,
    }
