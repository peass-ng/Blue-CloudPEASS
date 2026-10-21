"""AppFlow control-plane signals derived from an isolated S3-to-S3 lab."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_FLOW = re.compile(r"[A-Za-z0-9][A-Za-z0-9_!@#.-]{0,255}\Z")
_ROUTES = {
    "CreateFlow": ("AppflowFlowCreated", "request.appflow_flow_created", False),
    "DescribeFlow": ("AppflowFlowDescribed", "request.appflow_flow_described", True),
    "ListFlows": ("AppflowFlowsListed", "request.appflow_flows_listed", True),
    "DescribeFlowExecutionRecords": ("AppflowFlowExecutionRecordsRead", "request.appflow_flow_execution_records_read", True),
    "UpdateFlow": ("AppflowFlowScheduled", "request.appflow_flow_scheduled", False),
    "StopFlow": ("AppflowFlowStopped", "request.appflow_flow_stopped", False),
    "DeleteFlow": ("AppflowFlowDeleted", "request.appflow_flow_deleted", False),
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    if name == "StartFlow":
        route = ("AppflowFlowStartedOnDemand", "request.appflow_flow_started_on_demand", False)
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "appflow.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)
            or (not isinstance(request, Mapping) and not (name == "ListFlows" and request is None))):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []

    if name == "ListFlows":
        if request not in (None, {}):
            return []
        target = None
    else:
        flow = request.get("flowName")
        if not isinstance(flow, str) or not _FLOW.fullmatch(flow):
            return []
        target = f"arn:aws:appflow:{region}:{account}:flow/{flow}"

    if name in ("CreateFlow", "StartFlow", "StopFlow"):
        if not isinstance(response, Mapping) or response.get("flowArn") != target:
            return []
    if name == "CreateFlow":
        trigger = request.get("triggerConfig")
        if not isinstance(trigger, Mapping) or trigger.get("triggerType") not in ("OnDemand", "Scheduled", "Event"):
            return []
    if name == "UpdateFlow":
        trigger = request.get("triggerConfig")
        props = trigger.get("triggerProperties") if isinstance(trigger, Mapping) else None
        scheduled = props.get("Scheduled") if isinstance(props, Mapping) else None
        if (not isinstance(trigger, Mapping) or trigger.get("triggerType") != "Scheduled"
                or not isinstance(scheduled, Mapping)
                or not isinstance(scheduled.get("scheduleExpression"), str)
                or not scheduled["scheduleExpression"]
                or not isinstance(response, Mapping) or not isinstance(response.get("flowStatus"), str)):
            return []
    if name == "StartFlow":
        if not isinstance(response.get("flowStatus"), str):
            return []
        if isinstance(response.get("executionId"), str) and response["executionId"]:
            pass
        elif "executionId" not in response:
            route = ("AppflowFlowActivated", "request.appflow_flow_activated", False)
        else:
            return []
    if name == "StopFlow" and response.get("flowStatus") != "Suspended":
        return []
    if name == "DeleteFlow" and response not in (None, {}):
        return []

    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "appflow.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": target, flag: True,
    }]
