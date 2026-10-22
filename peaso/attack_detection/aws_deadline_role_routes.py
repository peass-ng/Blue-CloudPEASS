"""Bounded Deadline Cloud role assignments and credential-vending sequences."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9-]{1,128}\Z")
_ROLE = re.compile(r"arn:(?:aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}\Z")
_WRITES = {"CreateQueue", "UpdateQueue", "CreateFleet", "UpdateFleet", "CreateWorker"}
_READS = {"AssumeQueueRoleForUser", "AssumeFleetRoleForWorker"}


def _view(record: Mapping[str, Any]) -> tuple[datetime, str, str, str, str, Mapping[str, Any]] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "deadline.amazonaws.com"
            or name not in _WRITES | _READS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in _READS)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, stamp, event_id = (record.get("recipientAccountId"),
                                         record.get("awsRegion"), record.get("eventTime"),
                                         record.get("eventID"))
    identity = record.get("userIdentity")
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(stamp, str) or not isinstance(event_id, str) or not event_id
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))):
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except ValueError:
        return None
    return when, account, region, event_id, identity["arn"], request


def _id(request: Mapping[str, Any], key: str) -> str | None:
    value = request.get(key)
    return value if isinstance(value, str) and _ID.fullmatch(value) else None


def _target(account: str, region: str, farm: str, kind: str, resource: str) -> str:
    return "sha256:" + hashlib.sha256(
        f"deadline:{account}:{region}:{farm}:{kind}:{resource}".encode("utf-8")
    ).hexdigest()[:24]


def _event(record: Mapping[str, Any], view: tuple[datetime, str, str, str, str, Mapping[str, Any]],
           kind: str, resource: str, flag: str) -> dict[str, Any]:
    _, account, region, event_id, actor, request = view
    return {
        "cloud.provider": "aws", "event.source": "deadline.amazonaws.com",
        "event.name": record["eventName"], "event.outcome": "success",
        "event.id": event_id, "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor,
        "target.id": _target(account, region, request["farmId"], kind, resource),
        flag: True,
    }


def normalize_aws_deadline_role_route(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Record accepted role assignments without copying the role ARN or request."""
    view = _view(record)
    if view is None or record.get("eventName") not in {"CreateQueue", "UpdateQueue", "CreateFleet", "UpdateFleet"}:
        return None
    _, account, _, _, _, request = view
    farm = _id(request, "farmId")
    role = request.get("roleArn")
    if not farm or not isinstance(role, str):
        return None
    match = _ROLE.fullmatch(role)
    if not match or match.group(1) != account:
        return None
    name = record["eventName"]
    if name in {"CreateQueue", "UpdateQueue"}:
        response = record.get("responseElements")
        resource = _id(request, "queueId") if name == "UpdateQueue" else (
            _id(response, "queueId") if isinstance(response, Mapping) else None)
        flag = ("request.deadline_queue_role_update_requested" if name == "UpdateQueue"
                else "request.deadline_queue_role_created")
        kind = "queue"
    else:
        response = record.get("responseElements")
        resource = (_id(request, "fleetId") if name == "UpdateFleet" else
                    _id(response, "fleetId") if isinstance(response, Mapping) else None)
        if name == "CreateFleet":
            config = request.get("configuration")
            if not isinstance(config, Mapping) or not isinstance(config.get("customerManaged"), Mapping):
                return None
        flag = ("request.deadline_fleet_role_update_requested" if name == "UpdateFleet"
                else "request.deadline_customer_managed_fleet_role_created")
        kind = "fleet"
    if resource is None:
        return None
    return _event(record, view, kind, resource, flag)


def correlate_aws_deadline_role_vending(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Match only same actor/account/region/resource within a thirty-minute window."""
    ordered = []
    for record in records:
        view = _view(record)
        if view is None:
            continue
        when, account, region, event_id, actor, request = view
        farm = _id(request, "farmId")
        if farm is None:
            continue
        name = record["eventName"]
        resource = _id(request, "queueId" if name in {"UpdateQueue", "AssumeQueueRoleForUser"}
                       else "fleetId")
        if name in {"CreateWorker", "AssumeFleetRoleForWorker"}:
            worker = (_id(request, "workerId") if name == "AssumeFleetRoleForWorker" else
                      _id(record.get("responseElements"), "workerId")
                      if isinstance(record.get("responseElements"), Mapping) else None)
        else:
            worker = None
        if resource is None or (name in {"CreateWorker", "AssumeFleetRoleForWorker"} and worker is None):
            continue
        if name == "UpdateQueue" and normalize_aws_deadline_role_route(record) is None:
            continue
        ordered.append((when, 0 if name in {"CreateWorker", "UpdateQueue"} else 1,
                        event_id, account, region, farm, resource, worker, actor, record))
    ordered.sort(key=lambda item: item[:3])
    registered: dict[tuple[str, ...], tuple[datetime, str]] = {}
    updated: dict[tuple[str, ...], tuple[datetime, str]] = {}
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for when, _, event_id, account, region, farm, resource, worker, actor, record in ordered:
        name = record["eventName"]
        if name == "CreateWorker":
            registered[(account, region, farm, resource, worker, actor)] = (when, event_id)
            continue
        if name == "UpdateQueue":
            updated[(account, region, farm, resource, actor)] = (when, event_id)
            continue
        if name == "AssumeFleetRoleForWorker":
            earlier = registered.get((account, region, farm, resource, worker, actor))
            flag = "request.deadline_worker_role_vended_after_registration"
            kind = "worker"
            target_resource = f"{resource}:{worker}"
        elif name == "AssumeQueueRoleForUser":
            earlier = updated.get((account, region, farm, resource, actor))
            flag = "request.deadline_queue_role_vended_after_update"
            kind = "queue"
            target_resource = resource
        else:
            continue
        if earlier is None or not timedelta(0) <= when - earlier[0] <= timedelta(minutes=30):
            continue
        if event_id in seen:
            continue
        seen.add(event_id)
        finding = _event(record, (when, account, region, event_id, actor, record["requestParameters"]),
                         kind, target_resource, flag)
        finding["correlation_evidence"] = {"configuration_event_id": earlier[1]}
        result.append(finding)
    return result
