"""Accepted FHIR $erase submissions, without clinical identifiers or bodies."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_STORE = re.compile(r"[0-9a-f]{32}\Z")
_ERASE = re.compile(r"erase_([A-Z][A-Za-z]{2,63})_(.{1,128})\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report an accepted erase job request; job completion needs separate evidence."""
    if (record.get("eventSource") != "healthlake.amazonaws.com"
            or record.get("eventName") != "StartFHIRBulkDeleteJob"
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
            or str(response.get("statusCode")) != "200"
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    store, kind = request.get("datastoreId"), request.get("bulkDeleteType")
    if (not isinstance(store, str) or not _STORE.fullmatch(store)
            or not isinstance(kind, str) or not _ERASE.fullmatch(kind)):
        return None
    target = "sha256:" + hashlib.sha256(
        ":".join((account, region, store, kind)).encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "healthlake.amazonaws.com",
        "event.name": "StartFHIRBulkDeleteJob", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthlake_fhir_erase_submitted": True,
    }
