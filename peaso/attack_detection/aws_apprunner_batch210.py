"""Conservative App Runner service and runtime-configuration signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")


def _map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Emit a hash-only finding when accepted configuration supports the signal."""
    name = record.get("eventName")
    if (record.get("eventSource") != "apprunner.amazonaws.com"
            or name not in {"CreateService", "UpdateService"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return None
    try:
        if datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00")).tzinfo is None:
            return None
    except ValueError:
        return None
    request = _map(record.get("requestParameters"))
    service = _map(_map(record.get("responseElements")).get("service"))
    arn = service.get("serviceArn")
    service_prefix = f"arn:aws:apprunner:{region}:{account}:service/"
    if not isinstance(arn, str) or not arn.startswith(service_prefix) or len(arn) <= len(service_prefix):
        return None
    identity = _map(record.get("userIdentity"))
    if (identity.get("type") == "AWSService" or identity.get("invokedBy")
            or identity.get("accountId") != account):
        return None
    if name == "CreateService":
        requested = _map(request.get("instanceConfiguration")).get("instanceRoleArn")
        confirmed = _map(service.get("instanceConfiguration")).get("instanceRoleArn")
        role_prefix = f"arn:aws:iam::{account}:role/"
        if (not isinstance(requested, str)
                or not requested.startswith(role_prefix) or len(requested) <= len(role_prefix)
                or requested != confirmed
                or not isinstance(request.get("serviceName"), str)
                or request["serviceName"] != service.get("serviceName")
                or not _map(request.get("sourceConfiguration"))):
            return None
        field = "request.apprunner_service_created_with_instance_role"
    else:
        if request.get("serviceArn") != arn:
            return None
        source = _map(request.get("sourceConfiguration"))
        image = _map(_map(source.get("imageRepository")).get("imageConfiguration"))
        code = _map(_map(source.get("codeRepository")).get("codeConfiguration"))
        values = _map(code.get("codeConfigurationValues"))
        changed = any(key in item for item in (image, values) for key in
                      ("runtimeEnvironmentVariables", "runtimeEnvironmentSecrets", "startCommand"))
        if not changed:
            return None
        field = "request.apprunner_runtime_configuration_updated"
    return {
        "cloud.provider": "aws", "event.source": "apprunner.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": "sha256:" + hashlib.sha256(arn.encode()).hexdigest()[:24],
        field: True,
    }
