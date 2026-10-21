"""AppFlow configuration updates and bounded scheduled-activation correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any

from .aws_appflow_s3_batch126 import _ACCOUNT, _FLOW, _REGION, normalize as normalize_appflow


def normalize_update(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    if (record.get("eventSource") != "appflow.amazonaws.com"
            or record.get("eventName") != "UpdateFlow"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return []
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")
            or not isinstance(response.get("flowStatus"), str)
            or not isinstance(request.get("flowName"), str)
            or not _FLOW.fullmatch(request["flowName"])
            or not isinstance(request.get("triggerConfig"), Mapping)
            or request["triggerConfig"].get("triggerType") not in ("OnDemand", "Scheduled", "Event")
            or not all(field in request for field in ("sourceFlowConfig", "destinationFlowConfigList", "tasks"))
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    return [{
        "cloud.provider": "aws", "event.source": "appflow.amazonaws.com",
        "event.name": "AppflowFlowUpdated", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": f"arn:aws:appflow:{region}:{account}:flow/{request['flowName']}",
        "request.appflow_flow_updated": True,
    }]


def correlate_schedule_activation(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    updates: dict[tuple[str, str], list[tuple[datetime, dict[str, Any]]]] = {}
    activations: list[tuple[datetime, dict[str, Any]]] = []
    for record in records:
        if record.get("eventName") == "UpdateFlow" and not normalize_update(record):
            continue
        for event in normalize_appflow(record):
            name = event["event.name"]
            if name not in ("AppflowFlowScheduled", "AppflowFlowActivated"):
                continue
            when = datetime.fromisoformat(event["event.time"].replace("Z", "+00:00"))
            key = (event["account.id"], event["target.id"])
            if name == "AppflowFlowScheduled":
                updates.setdefault(key, []).append((when, event))
            else:
                activations.append((when, event))
    out = []
    for when, activation in activations:
        key = (activation["account.id"], activation["target.id"])
        candidates = [(t, update) for t, update in updates.get(key, ())
                      if timedelta(0) <= when - t <= timedelta(minutes=15)]
        if not candidates:
            continue
        _, update = max(candidates, key=lambda pair: pair[0])
        out.append({
            "cloud.provider": "aws", "event.source": "appflow.amazonaws.com",
            "event.name": "AppflowScheduledUpdateAndActivation", "event.outcome": "success",
            "event.id": activation["event.id"], "event.time": activation["event.time"],
            "account.id": activation["account.id"], "actor.id": activation["actor.id"],
            "target.id": activation["target.id"],
            "request.appflow_scheduled_update_and_activation": True,
            "correlation_evidence": {"scheduled_update_event_id": update["event.id"]},
        })
    return out
