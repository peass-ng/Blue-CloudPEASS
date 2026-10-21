"""B2BI transformer persistence and configuration inventory signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_IDS = {
    "profile": re.compile(r"p-[A-Za-z0-9_-]+\Z"),
    "transformer": re.compile(r"tr-[A-Za-z0-9_-]+\Z"),
    "capability": re.compile(r"ca-[A-Za-z0-9_-]+\Z"),
    "partnership": re.compile(r"ps-[A-Za-z0-9_-]+\Z"),
}
_ROUTES = {
    "CreateTransformer": ("B2biTransformerCreated", "request.b2bi_transformer_created", False),
    "UpdateTransformer": ("B2biTransformerActivated", "request.b2bi_transformer_activated", False),
    "CreateCapability": ("B2biCapabilityCreated", "request.b2bi_capability_created", False),
    "CreatePartnership": ("B2biPartnershipCreated", "request.b2bi_partnership_created", False),
    "ListTagsForResource": ("B2biResourceTagsRead", "request.b2bi_resource_tags_read", True),
    "TagResource": ("B2biResourceTagged", "request.b2bi_resource_tagged", False),
    "UntagResource": ("B2biResourceUntagged", "request.b2bi_resource_untagged", False),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _arn(value: Any, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:b2bi:{region}:{account}:"
    tail = value[len(prefix):] if value.startswith(prefix) else ""
    kind, slash, ident = tail.partition("/")
    if not slash or kind not in _IDS or not _IDS[kind].fullmatch(ident):
        return None
    return value


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

    result = _mapping(response)
    target = None
    if name == "CreateTransformer":
        ident = result.get("transformerId")
        if (not isinstance(ident, str) or not _IDS["transformer"].fullmatch(ident)
                or not isinstance(request.get("name"), str) or not request["name"]
                or result.get("status") != "inactive"):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:transformer/{ident}"
    elif name == "UpdateTransformer":
        ident = request.get("transformerId")
        if (not isinstance(ident, str) or not _IDS["transformer"].fullmatch(ident)
                or request.get("status") != "active"
                or result.get("transformerId") != ident
                or result.get("status") != "active"):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:transformer/{ident}"
    elif name == "CreateCapability":
        ident = result.get("capabilityId")
        edi = _mapping(_mapping(request.get("configuration")).get("edi"))
        if (not isinstance(ident, str) or not _IDS["capability"].fullmatch(ident)
                or request.get("type") != "edi" or not edi
                or not isinstance(request.get("name"), str) or not request["name"]):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:capability/{ident}"
    elif name == "CreatePartnership":
        ident = result.get("partnershipId")
        profile = request.get("profileId")
        capabilities = request.get("capabilities")
        if (not isinstance(ident, str) or not _IDS["partnership"].fullmatch(ident)
                or not isinstance(profile, str) or not _IDS["profile"].fullmatch(profile)
                or result.get("profileId") != profile
                or not isinstance(capabilities, list) or not capabilities
                or not all(isinstance(v, str) and _IDS["capability"].fullmatch(v)
                           for v in capabilities)):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:partnership/{ident}"
    else:
        raw_target = request.get("resourceARN", request.get("resourceArn"))
        if "resourceARN" in request and "resourceArn" in request and request["resourceARN"] != request["resourceArn"]:
            return []
        target = _arn(raw_target, region, account)
        if target is None:
            return []
        if name == "TagResource":
            tags = request.get("tags")
            if not isinstance(tags, list) or not tags or not all(
                    isinstance(v, Mapping) and isinstance(v.get("key"), str)
                    and v.get("key") for v in tags):
                return []
        elif name == "UntagResource":
            keys = request.get("tagKeys")
            if not isinstance(keys, list) or not keys or not all(
                    isinstance(v, str) and v for v in keys):
                return []

    identity = _mapping(record.get("userIdentity"))
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "b2bi.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }]
