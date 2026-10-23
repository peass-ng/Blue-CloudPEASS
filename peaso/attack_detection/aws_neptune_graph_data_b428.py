"""Neptune Analytics data-plane query events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_GRAPH = re.compile(r"g-[a-z0-9]{8,32}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report graph query use without inferring read/write from redacted SQL."""
    if (record.get("eventSource") != "neptune-graph.amazonaws.com"
            or record.get("eventName") != "ExecuteQuery"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Data"
            or record.get("managementEvent") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response, resources = (record.get("userIdentity"),
                                              record.get("requestParameters"),
                                              record.get("responseElements"),
                                              record.get("resources"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or identity.get("type") == "AWSService"
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(resources, list)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    if (request.get("requestType") != "POST"
            or str(response.get("responseCode")) != "200"):
        return None
    graphs = [item for item in resources if isinstance(item, Mapping)
              and item.get("type") == "AWS::NeptuneGraph::Graph"
              and item.get("accountId") == account
              and isinstance(item.get("ARN"), str)
              and item["ARN"].startswith(f"arn:aws:neptune-graph:{region}:{account}:graph/")
              and _GRAPH.fullmatch(item["ARN"].rsplit("/", 1)[-1])]
    if len(graphs) != 1:
        return None
    target = "sha256:" + hashlib.sha256(graphs[0]["ARN"].encode()).hexdigest()[:24]
    return {
        "cloud.provider": "aws", "event.source": "neptune-graph.amazonaws.com",
        "event.name": "ExecuteQuery", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"], "target.id": target,
        "request.neptune_graph_query_executed": True,
    }
