"""Accepted HealthLake FHIR import/export submissions with hashed S3 routes."""

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
_EVENTS = {
    "StartFHIRImportJob": ("jobOutputDataConfig", "request.healthlake_import_submitted"),
    "StartFHIRExportJob": ("outputDataConfig", "request.healthlake_export_submitted"),
}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Job completion, role permissions and data delivery need later evidence."""
    name = record.get("eventName")
    if (record.get("eventSource") != "healthlake.amazonaws.com"
            or name not in _EVENTS
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
            or response.get("jobStatus") != "SUBMITTED"
            or not isinstance(response.get("jobId"), str) or not response["jobId"]
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    store, role = request.get("datastoreId"), request.get("dataAccessRoleArn")
    if (not isinstance(store, str) or not _STORE.fullmatch(store)
            or response.get("datastoreId") != store
            or not isinstance(role, str) or not (match := _ROLE.fullmatch(role))
            or match.group(1) != account):
        return None
    config = request.get(_EVENTS[name][0])
    if not isinstance(config, Mapping):
        return None
    s3_config = config.get("s3Configuration")
    if not isinstance(s3_config, Mapping):
        return None
    output_uri = s3_config.get("s3Uri")
    if not isinstance(output_uri, str) or not _S3.fullmatch(output_uri):
        return None
    input_uri = ""
    if name == "StartFHIRImportJob":
        input_config = request.get("inputDataConfig")
        if not isinstance(input_config, Mapping):
            return None
        input_uri = input_config.get("s3Uri")
        if not isinstance(input_uri, str) or not _S3.fullmatch(input_uri):
            return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    target = "sha256:" + hashlib.sha256(
        ":".join((account, region, store, role, input_uri, output_uri)).encode()
    ).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "healthlake.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        _EVENTS[name][1]: True,
    }
