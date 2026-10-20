"""Correlate API Gateway portal public authorization update and publication."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    prepared = []
    for record in records:
        if (record.get("eventSource") != "apigateway.amazonaws.com"
                or record.get("eventName") not in {"UpdatePortal", "PublishPortal", "DisablePortal", "DeletePortal"}
                or record.get("eventCategory") != "Management"
                or record.get("eventType") != "AwsApiCall"
                or record.get("managementEvent") is not True
                or record.get("readOnly") is not False
                or record.get("errorCode") or record.get("errorMessage")):
            continue
        request = record.get("requestParameters")
        identity = record.get("userIdentity")
        account, region = record.get("recipientAccountId"), record.get("awsRegion")
        when, event_id = _when(record.get("eventTime")), record.get("eventID")
        if (not isinstance(request, Mapping) or not isinstance(identity, Mapping)
                or not isinstance(account, str) or not account.isdigit() or len(account) != 12
                or not isinstance(region, str) or not region
                or not isinstance(when, datetime) or not isinstance(event_id, str) or not event_id):
            continue
        portal_id, actor = request.get("portalId"), identity.get("arn")
        if (not isinstance(portal_id, str) or not portal_id
                or not isinstance(actor, str) or not actor.startswith("arn:")):
            continue
        prepared.append((when, event_id, account, region, portal_id, actor, record))

    latest_auth: dict[tuple[str, str, str], tuple[datetime, str, str] | None] = {}
    out = []
    for when, event_id, account, region, portal_id, actor, record in sorted(
            prepared, key=lambda row: (row[0], row[1])):
        key = (account, region, portal_id)
        name = record["eventName"]
        if name == "UpdatePortal":
            request, response = record["requestParameters"], record.get("responseElements")
            auth = request.get("authorization")
            if not isinstance(auth, Mapping):
                continue
            is_public = ("none" in auth and isinstance(auth["none"], Mapping)
                         and isinstance(response, Mapping)
                         and response.get("portalId") == portal_id
                         and isinstance(response.get("authorization"), Mapping)
                         and "none" in response["authorization"])
            latest_auth[key] = (when, event_id, actor) if is_public else None
        elif name in {"DisablePortal", "DeletePortal"}:
            latest_auth[key] = None
        elif name == "PublishPortal":
            prior = latest_auth.get(key)
            if prior is None:
                continue
            earlier, update_id, update_actor = prior
            if update_actor != actor or not timedelta(0) <= when - earlier <= timedelta(hours=1):
                continue
            out.append({"cloud.provider": "aws", "event.source": "apigateway.amazonaws.com",
                        "event.name": "ApiGatewayPortalPublicAuthPublished",
                        "event.outcome": "success", "event.id": event_id,
                        "event.time": record["eventTime"], "account.id": account,
                        "actor.id": actor, "target.id": portal_id,
                        "request.apigateway_portal_public_auth_published": True})
            latest_auth[key] = None
    return out
