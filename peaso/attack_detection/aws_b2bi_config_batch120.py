"""B2BI configuration discovery, update and deletion control signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_PROFILE_ID = re.compile(r"p-[A-Za-z0-9_-]+\Z")
_TRANSFORMER_ID = re.compile(r"tr-[A-Za-z0-9_-]+\Z")
_ROUTES = {
    "ListProfiles": ("B2biProfilesListed", "request.b2bi_profiles_listed", True, "profile"),
    "GetProfile": ("B2biProfileRead", "request.b2bi_profile_read", True, "profile"),
    "UpdateProfile": ("B2biProfileUpdated", "request.b2bi_profile_updated", False, "profile"),
    "DeleteProfile": ("B2biProfileDeleted", "request.b2bi_profile_deleted", False, "profile"),
    "ListTransformers": ("B2biTransformersListed", "request.b2bi_transformers_listed", True, "transformer"),
    "GetTransformer": ("B2biTransformerRead", "request.b2bi_transformer_read", True, "transformer"),
    "UpdateTransformer": ("B2biTransformerUpdated", "request.b2bi_transformer_updated", False, "transformer"),
    "DeleteTransformer": ("B2biTransformerDeleted", "request.b2bi_transformer_deleted", False, "transformer"),
}


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
    if name.startswith("List"):
        target = f"arn:aws:b2bi:{region}:{account}:{kind}"
    else:
        key = "profileId" if kind == "profile" else "transformerId"
        value = request.get(key)
        pattern = _PROFILE_ID if kind == "profile" else _TRANSFORMER_ID
        if not isinstance(value, str) or not pattern.fullmatch(value):
            return []
        target = f"arn:aws:b2bi:{region}:{account}:{kind}/{value}"
    if name.startswith("Update"):
        key = "profileId" if kind == "profile" else "transformerId"
        if not any(k != key for k in request):
            return []

    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return [{
        "cloud.provider": "aws", "event.source": "b2bi.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }]
