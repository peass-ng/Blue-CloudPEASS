"""Accepted HealthLake FHIR reads, searches and writes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_STORE = re.compile(r"[0-9a-f]{32}\Z")
_TYPE = re.compile(r"[A-Z][A-Za-z]{2,63}\Z")
_EVENTS = {
    "CreateResource": (False, 201, True, False),
    "UpdateResource": (False, 200, True, True),
    "DeleteResource": (False, 204, True, True),
    "ProcessBundle": (False, 200, False, False),
    "SearchEverything": (True, None, True, True),
    "SearchWithGet": (True, None, True, False),
    "SearchWithPost": (True, None, True, False),
    "ReadResource": (True, None, True, True),
    "GetHistoryByResourceId": (True, None, True, True),
    "VersionReadResource": (True, None, True, True),
    "PatchResource": (False, 200, True, True),
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Hash FHIR targets and discard headers, query terms and clinical bodies."""
    name = record.get("eventName")
    if (record.get("eventSource") != "healthlake.amazonaws.com"
            or name not in _EVENTS
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    store = request.get("datastoreId")
    if not isinstance(store, str) or not _STORE.fullmatch(store):
        return None
    expected_readonly, status, needs_type, needs_id = _EVENTS[name]
    if record.get("readOnly") is not expected_readonly:
        return None
    if status is not None:
        response = record.get("responseElements")
        if not isinstance(response, Mapping) or str(response.get("statusCode")) != str(status):
            return None
    elif isinstance(record.get("responseElements"), Mapping):
        response_status = record["responseElements"].get("statusCode")
        if response_status is not None and str(response_status) != "200":
            return None
    resource_type = request.get("resourceType")
    resource_id = request.get("resourceId")
    if needs_type and (not isinstance(resource_type, str)
                       or not _TYPE.fullmatch(resource_type)):
        return None
    if needs_id and (not isinstance(resource_id, str) or not resource_id
                     or len(resource_id) > 128):
        return None
    version_id = request.get("versionId")
    if name == "VersionReadResource" and (not isinstance(version_id, str)
                                          or not version_id or len(version_id) > 128):
        return None
    if name == "SearchEverything" and resource_type != "Patient":
        return None
    target_parts = [account, region, store]
    if needs_type:
        target_parts.append(resource_type)
    if needs_id:
        target_parts.append(resource_id)
    if name == "VersionReadResource":
        target_parts.append(version_id)
    target = "sha256:" + hashlib.sha256(":".join(target_parts).encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "healthlake.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthlake_fhir_call": True,
    }
