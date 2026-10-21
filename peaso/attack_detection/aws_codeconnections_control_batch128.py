"""CodeConnections discovery and connection lifecycle signals."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_PROVIDERS = {"Bitbucket", "GitHub", "GitHubEnterpriseServer", "GitLab", "GitLabSelfManaged", "AzureDevOps"}
_ROUTES = {
    "CreateConnection": ("CodeConnectionsConnectionCreated", "request.codeconnections_connection_created", False),
    "GetConnection": ("CodeConnectionsConnectionRead", "request.codeconnections_connection_read", True),
    "ListConnections": ("CodeConnectionsConnectionsListed", "request.codeconnections_connections_listed", True),
    "ListHosts": ("CodeConnectionsHostsListed", "request.codeconnections_hosts_listed", True),
    "ListRepositoryLinks": ("CodeConnectionsRepositoryLinksListed", "request.codeconnections_repository_links_listed", True),
    "ListTagsForResource": ("CodeConnectionsConnectionTagsRead", "request.codeconnections_connection_tags_read", True),
    "TagResource": ("CodeConnectionsConnectionTagged", "request.codeconnections_connection_tagged", False),
    "UntagResource": ("CodeConnectionsConnectionUntagged", "request.codeconnections_connection_untagged", False),
    "DeleteConnection": ("CodeConnectionsConnectionDeleted", "request.codeconnections_connection_deleted", False),
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
            or (request is not None and not isinstance(request, Mapping))):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    request = request or {}

    if name == "CreateConnection":
        if (not isinstance(request.get("connectionName"), str)
                or not 1 <= len(request["connectionName"]) <= 32
                or request.get("providerType") not in _PROVIDERS
                or not isinstance(response, Mapping)):
            return []
        target = response.get("connectionArn")
    elif name in ("ListConnections", "ListHosts", "ListRepositoryLinks"):
        if not isinstance(request, Mapping):
            return []
        if name == "ListConnections" and request.get("providerTypeFilter") not in (None, *_PROVIDERS):
            return []
        if "maxResults" in request and (not isinstance(request["maxResults"], int)
                                        or isinstance(request["maxResults"], bool)
                                        or not 0 <= request["maxResults"] <= 100):
            return []
        target = None
    else:
        target = request.get("connectionArn") if name in ("GetConnection", "DeleteConnection") else request.get("resourceArn")

    if target is not None:
        if not isinstance(target, str):
            return []
        prefix = f"arn:aws:codeconnections:{region}:{account}:connection/"
        if not target.startswith(prefix) or not _UUID.fullmatch(target[len(prefix):]):
            return []
    elif name not in ("ListConnections", "ListHosts", "ListRepositoryLinks"):
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
