"""B2BI capability and partnership control signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CAPABILITY = re.compile(r"ca-[A-Za-z0-9_-]+\Z")
_PARTNERSHIP = re.compile(r"ps-[A-Za-z0-9_-]+\Z")
_PROFILE = re.compile(r"p-[A-Za-z0-9_-]+\Z")
_TRANSFORMER = re.compile(r"tr-[A-Za-z0-9_-]+\Z")
_ROUTES = {
    "ListCapabilities": ("B2biCapabilitiesListed", "request.b2bi_capabilities_listed", True, "capability"),
    "GetCapability": ("B2biCapabilityRead", "request.b2bi_capability_read", True, "capability"),
    "UpdateCapability": ("B2biCapabilityUpdated", "request.b2bi_capability_updated", False, "capability"),
    "DeleteCapability": ("B2biCapabilityDeleted", "request.b2bi_capability_deleted", False, "capability"),
    "ListPartnerships": ("B2biPartnershipsListed", "request.b2bi_partnerships_listed", True, "partnership"),
    "GetPartnership": ("B2biPartnershipRead", "request.b2bi_partnership_read", True, "partnership"),
    "UpdatePartnership": ("B2biPartnershipUpdated", "request.b2bi_partnership_updated", False, "partnership"),
    "DeletePartnership": ("B2biPartnershipDeleted", "request.b2bi_partnership_deleted", False, "partnership"),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name, account, region = (record.get(key) for key in
                             ("eventName", "recipientAccountId", "awsRegion"))
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "b2bi.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)):
        return []
    try:
        timestamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return []
    except ValueError:
        return []

    synthetic, flag, _, kind = route
    if name == "ListCapabilities":
        target = f"arn:aws:b2bi:{region}:{account}:capability"
    elif name == "ListPartnerships":
        value = request.get("profileId")
        if not isinstance(value, str) or not _PROFILE.fullmatch(value):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:profile/{value}"
    else:
        key = "capabilityId" if kind == "capability" else "partnershipId"
        value = request.get(key)
        pattern = _CAPABILITY if kind == "capability" else _PARTNERSHIP
        if not isinstance(value, str) or not pattern.fullmatch(value):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:{kind}/{value}"
    if name.startswith("Update"):
        key = "capabilityId" if kind == "capability" else "partnershipId"
        if not any(k != key and v is not None for k, v in request.items()):
            return []

    identity = _mapping(record.get("userIdentity"))
    common = {
        "cloud.provider": "aws", "event.source": "b2bi.amazonaws.com",
        "event.outcome": "success", "event.id": record["eventID"],
        "event.time": record["eventTime"], "account.id": account,
        "actor.id": identity.get("arn"), "target.id": target,
    }
    findings = [{**common, "event.name": synthetic, flag: True}]
    if name == "UpdateCapability":
        edi = _mapping(_mapping(request.get("configuration")).get("edi"))
        returned = _mapping(_mapping(response).get("configuration"))
        returned_edi = _mapping(returned.get("edi"))
        replacement = returned_edi.get("transformerId")
        if (edi and isinstance(replacement, str) and _TRANSFORMER.fullmatch(replacement)
                and _mapping(response).get("capabilityId") == value):
            findings.append({**common,
                             "event.name": "B2biCapabilityTransformerSelected",
                             "request.b2bi_capability_transformer_selected": True,
                             "transformer.id": replacement})
    return findings
