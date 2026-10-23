"""DataSync S3 role binding and scheduled task facts from management events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
import hashlib
from typing import Any, Iterable


_NAMES = {"CreateLocationS3", "UpdateLocationS3", "CreateTask"}


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def normalize_aws_datasync_s3_b436(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "datasync.amazonaws.com" or record.get("eventName") not in _NAMES:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    name = record["eventName"]
    config = request.get("s3Config")
    config = config if isinstance(config, Mapping) else {}
    role = config.get("bucketAccessRoleArn")
    role = role if isinstance(role, str) and role.startswith("arn:aws:iam::") and ":role/" in role else None
    bucket = request.get("s3BucketArn")
    bucket = bucket if isinstance(bucket, str) and bucket.startswith("arn:aws:s3:::") else None
    location = request.get("locationArn")
    location = location if isinstance(location, str) and ":location/" in location else None
    source = request.get("sourceLocationArn")
    destination = request.get("destinationLocationArn")
    task = response.get("taskArn") if isinstance(response, Mapping) else None
    schedule = request.get("schedule")
    schedule = schedule if isinstance(schedule, Mapping) else {}
    target = bucket if name == "CreateLocationS3" else location if name == "UpdateLocationS3" else task
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "datasync.amazonaws.com", "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"),
        "actor.id": _hash(identity["arn"]) if isinstance(identity.get("arn"), str) else None,
        "target.id": _hash(target) if isinstance(target, str) else None,
        "request.datasync_s3_role_bound": bool(not failed and name == "CreateLocationS3" and bucket and role),
        "request.datasync_s3_role_updated": bool(not failed and name == "UpdateLocationS3" and location and role),
        "request.datasync_s3_root_scope_requested": bool(not failed and name == "UpdateLocationS3"
                                                      and location and role and request.get("subdirectory") == "/"),
        "request.datasync_scheduled_task_created": bool(not failed and name == "CreateTask"
                                                       and isinstance(source, str) and ":location/" in source
                                                       and isinstance(destination, str) and ":location/" in destination
                                                       and isinstance(task, str) and ":task/" in task
                                                       and schedule.get("status") == "ENABLED"
                                                       and isinstance(schedule.get("scheduleExpression"), str)
                                                       and bool(schedule["scheduleExpression"])),
    }


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate_aws_datasync_new_role_task_b436(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Join an actor's new S3 role binding, task creation, and task start."""
    locations: dict[tuple[str, str, str], tuple[datetime, Mapping[str, Any]]] = {}
    tasks: dict[tuple[str, str, str], tuple[datetime, str, str]] = {}
    starts: list[tuple[datetime, str, str, str, Mapping[str, Any]]] = []
    eligible = {"CreateLocationS3", "CreateTask", "StartTaskExecution"}
    for record in records:
        name = record.get("eventName")
        if name not in eligible or record.get("eventSource") != "datasync.amazonaws.com":
            continue
        if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
                or record.get("managementEvent") is not True or record.get("readOnly") is not False
                or record.get("errorCode") or record.get("errorMessage")):
            continue
        request = record.get("requestParameters")
        response = record.get("responseElements")
        identity = record.get("userIdentity")
        account = record.get("recipientAccountId")
        when = _when(record.get("eventTime"))
        if (not isinstance(request, Mapping) or not isinstance(response, Mapping)
                or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
                or not isinstance(account, str) or len(account) != 12 or not account.isdigit()
                or when is None or response.get("errorCode") or response.get("errorMessage")):
            continue
        actor = identity["arn"]
        if name == "CreateLocationS3":
            config = request.get("s3Config")
            role = config.get("bucketAccessRoleArn") if isinstance(config, Mapping) else None
            location = response.get("locationArn")
            bucket = request.get("s3BucketArn")
            if (isinstance(role, str) and role.startswith(f"arn:aws:iam::{account}:role/")
                    and isinstance(bucket, str) and bucket.startswith("arn:aws:s3:::")
                    and isinstance(location, str) and f":{account}:location/" in location):
                locations[(account, actor, location)] = when, record
        elif name == "CreateTask":
            task = response.get("taskArn")
            source, destination = request.get("sourceLocationArn"), request.get("destinationLocationArn")
            if (isinstance(task, str) and f":{account}:task/" in task
                    and isinstance(source, str) and f":{account}:location/" in source
                    and isinstance(destination, str) and f":{account}:location/" in destination):
                tasks[(account, actor, task)] = when, source, destination
        else:
            task = request.get("taskArn")
            execution = response.get("taskExecutionArn")
            if (isinstance(task, str) and f":{account}:task/" in task
                    and isinstance(execution, str) and execution.startswith(task + "/execution/")):
                starts.append((when, account, actor, task, record))
    result = []
    for when, account, actor, task, record in starts:
        created = tasks.get((account, actor, task))
        if created is None or not created[0] <= when <= created[0] + timedelta(hours=2):
            continue
        if not any(
            (location := locations.get((account, actor, arn))) is not None
            and location[0] <= created[0] <= location[0] + timedelta(hours=2)
            for arn in created[1:]
        ):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "datasync.amazonaws.com",
            "event.name": "StartTaskExecution", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": _hash(actor), "target.id": _hash(task),
            "request.datasync_new_role_task_started": True,
        })
    return result
