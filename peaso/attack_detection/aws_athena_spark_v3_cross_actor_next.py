"""Project bounded Athena PySpark 3 role/session and cross-actor notebook routes.

CloudTrail can contain a notebook bearer token and inline calculation code.
Neither field, the notebook payload, nor session/notebook IDs enter detections.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_NAMES = {"CreateWorkGroup", "CreateNotebook", "UpdateNotebook", "StartSession",
          "CreatePresignedNotebookUrl", "StartCalculationExecution"}


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _identity(value: Any, account: str) -> tuple[str, str] | None:
    if not isinstance(value, Mapping) or value.get("accountId") != account:
        return None
    actor = value.get("arn")
    if not isinstance(actor, str) or not actor.startswith("arn:"):
        return None
    if value.get("type") == "AssumedRole":
        context = value.get("sessionContext")
        issuer = context.get("sessionIssuer") if isinstance(context, Mapping) else None
        principal = issuer.get("arn") if isinstance(issuer, Mapping) else None
        if not isinstance(principal, str) or not principal.startswith("arn:"):
            return None
    else:
        principal = actor
    return actor, principal


def _valid(record: Mapping[str, Any]) -> tuple[str, str, str, str, datetime, Mapping, Mapping] | None:
    if (record.get("eventSource") != "athena.amazonaws.com"
            or record.get("eventName") not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    when, event_id = _when(record.get("eventTime")), record.get("eventID")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(event_id, str)
            or not event_id or when is None):
        return None
    identity = _identity(record.get("userIdentity"), account)
    if identity is None:
        return None
    actor, principal = identity
    return account, region, actor, principal, when, request, response if isinstance(response, Mapping) else {}


def _workgroup_arn(account: str, region: str, name: str) -> str:
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return f"arn:{partition}:athena:{region}:{account}:workgroup/{name}"


def normalize_create_workgroup(record: Mapping[str, Any]) -> dict[str, Any] | None:
    values = _valid(record)
    if values is None or record.get("eventName") != "CreateWorkGroup":
        return None
    account, region, actor, _, _, request, _ = values
    name, config = request.get("name"), request.get("configuration")
    if not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(config, Mapping):
        return None
    engine = config.get("engineVersion")
    role = config.get("executionRole")
    if (not isinstance(engine, Mapping)
            or engine.get("selectedEngineVersion") != "PySpark engine version 3"
            or not isinstance(role, str)
            or not re.fullmatch(rf"arn:aws(?:-us-gov|-cn)?:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role)):
        return None
    return {"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
            "event.name": "AthenaSparkExecutionRoleWorkGroupCreated", "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor,
            "target.id": _workgroup_arn(account, region, name),
            "request.athena_spark_execution_role_bound": True}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    workgroups = []
    notebooks = []
    sessions = []
    reads = []
    for record in records:
        values = _valid(record)
        if values is None:
            continue
        account, region, actor, principal, when, request, response = values
        name = record["eventName"]
        if name == "CreateWorkGroup":
            if normalize_create_workgroup(record) is not None:
                workgroups.append((when, account, region, principal, request["name"], record))
        elif name == "CreateNotebook":
            workgroup, notebook_id = request.get("workGroup"), response.get("notebookId")
            if (isinstance(workgroup, str) and _NAME.fullmatch(workgroup)
                    and isinstance(notebook_id, str) and _UUID.fullmatch(notebook_id)):
                notebooks.append((when, account, region, principal, workgroup, notebook_id, record))
        elif name == "StartSession":
            workgroup, session_id = request.get("workGroup"), response.get("sessionId")
            if (isinstance(workgroup, str) and _NAME.fullmatch(workgroup)
                    and isinstance(session_id, str) and _UUID.fullmatch(session_id)):
                sessions.append((when, account, region, principal, workgroup, session_id, record))
                reads.append((when, account, region, actor, principal, name, workgroup, session_id, record))
        elif name == "UpdateNotebook":
            notebook_id = request.get("notebookId")
            if isinstance(notebook_id, str) and _UUID.fullmatch(notebook_id):
                reads.append((when, account, region, actor, principal, name, None, notebook_id, record))
        elif name in {"CreatePresignedNotebookUrl", "StartCalculationExecution"}:
            session_id = request.get("sessionId")
            if isinstance(session_id, str) and _UUID.fullmatch(session_id):
                reads.append((when, account, region, actor, principal, name, None, session_id, record))
    out = []
    flag = {"StartSession": "request.athena_new_role_workgroup_session_started",
            "UpdateNotebook": "request.athena_cross_actor_notebook_updated",
            "CreatePresignedNotebookUrl": "request.athena_cross_actor_notebook_url_requested",
            "StartCalculationExecution": "request.athena_cross_actor_calculation_submitted"}
    for when, account, region, actor, principal, name, workgroup, identifier, record in reads:
        if name == "StartSession":
            candidates = [x for x in workgroups if x[1:4] == (account, region, principal)
                          and x[4] == workgroup and timedelta(0) <= when-x[0] <= timedelta(hours=1)]
        elif name == "UpdateNotebook":
            candidates = [x for x in notebooks if x[1:3] == (account, region)
                          and x[3] != principal and x[5] == identifier
                          and timedelta(0) <= when-x[0] <= timedelta(hours=24)]
        else:
            candidates = [x for x in sessions if x[1:3] == (account, region)
                          and x[3] != principal and x[5] == identifier
                          and timedelta(0) <= when-x[0] <= timedelta(hours=24)]
        if not candidates:
            continue
        start = max(candidates, key=lambda x: x[0])
        out.append({"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
                    "event.name": "AthenaSpark" + name, "event.outcome": "success",
                    "event.id": record["eventID"], "event.time": record["eventTime"],
                    "account.id": account, "actor.id": actor,
                    "target.id": _workgroup_arn(account, region, start[4]),
                    flag[name]: True,
                    "correlation_evidence": {"source_event_id": start[-1]["eventID"]}})
    return out
