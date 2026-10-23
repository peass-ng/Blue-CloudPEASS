"""Accepted HealthLake FHIR REST $export POST submissions."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_STORE = re.compile(r"[0-9a-f]{32}\Z")
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/.{1,512}\Z")
_S3 = re.compile(r"s3://[a-z0-9][a-z0-9.-]{2,62}(?:/.{0,1024})?\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """The REST response body may expose job or destination data; omit it."""
    if (record.get("eventSource") != "healthlake.amazonaws.com"
            or record.get("eventName") != "StartFHIRExportJobWithPost"
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
    store, params = request.get("datastoreId"), request.get("exportJobParameters")
    if (not isinstance(store, str) or not _STORE.fullmatch(store)
            or not isinstance(params, Mapping)):
        return None
    role = params.get("dataAccessRoleArn")
    if not isinstance(role, str) or not (match := _ROLE.fullmatch(role)) or match.group(1) != account:
        return None
    config = params.get("outputDataConfig")
    s3_config = config.get("s3Configuration") if isinstance(config, Mapping) else None
    uri = s3_config.get("s3Uri") if isinstance(s3_config, Mapping) else None
    if not isinstance(uri, str) or not _S3.fullmatch(uri):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    target = "sha256:" + hashlib.sha256(
        ":".join((account, region, store, role, uri)).encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "healthlake.amazonaws.com",
        "event.name": "StartFHIRExportJobWithPost", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.healthlake_rest_export_post_submitted": True,
    }
