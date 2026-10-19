"""SSM document public sharing and high-capacity hybrid activations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any


def _date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def normalize_aws_ssm_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ssm.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"ModifyDocumentPermission", "CreateActivation"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    now, expiry = _date(record.get("eventTime")), _date(request.get("expirationDate"))
    long_lived = now is not None and expiry is not None and expiry >= now + timedelta(days=14)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "ssm.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": request.get("name") if name == "ModifyDocumentPermission" else response.get("activationId") if isinstance(response, Mapping) else None,
        "request.ssm_document_public_share_added": (
            not failed and name == "ModifyDocumentPermission"
            and isinstance(request.get("name"), str) and bool(request["name"])
            and request.get("permissionType") == "Share"
            and isinstance(request.get("accountIdsToAdd"), list)
            and "all" in request["accountIdsToAdd"]
        ),
        "request.ssm_activation_high_capacity_long_expiry": (
            not failed and name == "CreateActivation" and isinstance(response, Mapping)
            and isinstance(response.get("activationId"), str) and bool(response["activationId"])
            and type(request.get("registrationLimit")) is int and request["registrationLimit"] >= 20
            and isinstance(request.get("iamRole"), str) and bool(request["iamRole"])
            and long_lived
        ),
    }
