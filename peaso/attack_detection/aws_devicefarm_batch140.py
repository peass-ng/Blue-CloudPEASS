"""Device Farm reads, signed URL issuance, and destructive API calls."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
_ROUTES = {
    "GetProject": ("ProjectConfigurationRead", "request.devicefarm_project_configuration_read", "project", True, "arn"),
    "ListRuns": ("ProjectRunsListed", "request.devicefarm_runs_listed", "project", True, "arn"),
    "ListUploads": ("ProjectUploadsListed", "request.devicefarm_uploads_listed", "project", True, "arn"),
    "GetUpload": ("UploadUrlRequested", "request.devicefarm_upload_url_requested", "upload", True, "arn"),
    "CreateTestGridUrl": ("TestGridUrlCreated", "request.devicefarm_testgrid_url_created", "testgrid-project", False, "projectArn"),
    "DeleteUpload": ("UploadDeleted", "request.devicefarm_upload_deleted", "upload", False, "arn"),
    "DeleteProject": ("ProjectDeleted", "request.devicefarm_project_deleted", "project", False, "arn"),
    "DeleteTestGridProject": ("TestGridProjectDeleted", "request.devicefarm_testgrid_project_deleted", "testgrid-project", False, "projectArn"),
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    if route is None:
        return []
    synthetic, marker, kind, read_only, parameter = route
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    if (record.get("eventSource") != "devicefarm.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read_only
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    arn = request.get(parameter)
    resource_suffix = _UUID + (r"/" + _UUID if kind == "upload" else "")
    expected = rf"arn:aws:devicefarm:{re.escape(region)}:{account}:{kind}:{resource_suffix}\Z"
    if not isinstance(arn, str) or not re.fullmatch(expected, arn):
        return []
    if name == "CreateTestGridUrl":
        seconds = request.get("expiresInSeconds")
        response = record.get("responseElements")
        if (not isinstance(seconds, int) or not 60 <= seconds <= 86400
                or not isinstance(response, Mapping)
                or not isinstance(response.get("url"), str)
                or (response["url"] != "HIDDEN_DUE_TO_SECURITY_REASONS"
                    and not response["url"].startswith("https://"))):
            return []
    actor = record.get("userIdentity")
    return [{
        "cloud.provider": "aws", "event.source": "devicefarm.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": arn,
        marker: True,
    }]
