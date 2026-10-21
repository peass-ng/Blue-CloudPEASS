"""CodeConnections host discovery, tagging and lifecycle signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_HOST_ID = re.compile(r"[A-Za-z0-9-]{3,64}\Z")
_ROUTES = {
    "CreateHost": ("CodeConnectionsHostCreated", "request.codeconnections_host_created", False),
    "GetHost": ("CodeConnectionsHostRead", "request.codeconnections_host_read", True),
    "ListTagsForResource": ("CodeConnectionsHostTagsRead", "request.codeconnections_host_tags_read", True),
    "TagResource": ("CodeConnectionsHostTagged", "request.codeconnections_host_tagged", False),
    "UntagResource": ("CodeConnectionsHostUntagged", "request.codeconnections_host_untagged", False),
    "DeleteHost": ("CodeConnectionsHostDeleted", "request.codeconnections_host_deleted", False),
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "codeconnections.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or not isinstance(request, Mapping)):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []

    if name == "CreateHost":
        if (not isinstance(request.get("name"), str) or not request["name"]
                or request.get("providerType") != "GitHubEnterpriseServer"
                or not isinstance(request.get("providerEndpoint"), str)
                or not request["providerEndpoint"]
                or not isinstance(response, Mapping)):
            return []
        target = response.get("hostArn")
    else:
        target = request.get("hostArn") if name in ("GetHost", "DeleteHost") else request.get("resourceArn")
    if not isinstance(target, str):
        return []
    prefix = f"arn:aws:codeconnections:{region}:{account}:host/"
    if not target.startswith(prefix) or not _HOST_ID.fullmatch(target[len(prefix):]):
        return []
    if name == "TagResource":
        tags = request.get("tags")
        if not isinstance(tags, list) or not tags or not all(
                isinstance(tag, Mapping) and isinstance(tag.get("key"), str)
                and tag["key"] and isinstance(tag.get("value"), str) for tag in tags):
            return []
    if name == "UntagResource":
        keys = request.get("tagKeys")
        if not isinstance(keys, list) or not keys or not all(isinstance(key, str) and key for key in keys):
            return []

    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "codeconnections.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": target, flag: True,
    }]
