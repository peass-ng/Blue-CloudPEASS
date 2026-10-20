"""Narrow CloudFormation input-change correlations and StackSet operations."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _common(record: Mapping[str, Any]) -> tuple[str, str, str, Mapping[str, Any], Mapping[str, Any]] | None:
    if (record.get("errorCode") or record.get("errorMessage")
            or record.get("readOnly") is not False
            or record.get("eventType") != "AwsApiCall"):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request, response = record.get("userIdentity"), record.get("requestParameters"), record.get("responseElements")
    if (not isinstance(account, str) or len(account) != 12 or not account.isdigit()
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)):
        return None
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return None
    return account, region, identity["arn"], request, response if isinstance(response, Mapping) else {}


def normalize_stackset(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "cloudformation.amazonaws.com"
            or name not in {"CreateStackSet", "CreateStackInstances", "UpdateStackSet"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True):
        return None
    common = _common(record)
    if common is None:
        return None
    account, region, actor, request, response = common
    stackset = request.get("stackSetName")
    if not isinstance(stackset, str) or not stackset:
        return None
    selected = False
    if name == "CreateStackSet":
        role = request.get("administrationRoleARN")
        selected = (request.get("permissionModel") == "SELF_MANAGED"
                    and isinstance(role, str) and role.startswith(f"arn:aws:iam::{account}:role/")
                    and isinstance(request.get("executionRoleName"), str)
                    and bool(request["executionRoleName"])
                    and isinstance(response.get("stackSetId"), str))
    elif name == "CreateStackInstances":
        selected = (isinstance(request.get("regions"), list)
                    and region in request["regions"]
                    and isinstance(response.get("operationId"), str))
    else:
        role = request.get("administrationRoleARN")
        selected = (isinstance(role, str)
                    and role.startswith(f"arn:aws:iam::{account}:role/")
                    and isinstance(response.get("operationId"), str))
    if not selected:
        return None
    return {"cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record.get("eventID"),
            "event.time": record.get("eventTime"), "account.id": account,
            "actor.id": actor, "target.id": stackset,
            "request.cfn_stackset_self_managed_roles_created": name == "CreateStackSet",
            "request.cfn_stackset_region_instances_created": name == "CreateStackInstances",
            "request.cfn_stackset_admin_role_passed_update": name == "UpdateStackSet"}


def correlate_inputs(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Correlate limited actor writes and later updates; no secret/template content escapes."""
    writes: list[tuple[datetime, str, str, str, str]] = []
    updates: list[tuple[datetime, str, str, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        common = _common(record)
        when = _time(record.get("eventTime"))
        if common is None or when is None:
            continue
        account, region, actor, req, _ = common
        source, name = record.get("eventSource"), record.get("eventName")
        if (source == "ssm.amazonaws.com" and name == "PutParameter"
                and record.get("eventCategory") == "Management"
                and req.get("overwrite") is True and isinstance(req.get("name"), str)
                and record.get("userIdentity", {}).get("invokedBy") != "cloudformation.amazonaws.com"):
            writes.append((when, account, region, actor, "ssm"))
        elif (source == "s3.amazonaws.com" and name == "PutObject"
              and record.get("eventCategory") == "Data"
              and isinstance(req.get("key"), str)
              and ("template" in req["key"].lower() or "nested" in req["key"].lower())
              and req["key"].lower().endswith((".json", ".yaml", ".yml"))):
            writes.append((when, account, region, actor, "s3"))
        elif (source == "cloudformation.amazonaws.com" and name == "UpdateStack"
              and record.get("eventCategory") == "Management"
              and record.get("managementEvent") is True
              and isinstance(req.get("stackName"), str)):
            updates.append((when, account, region, actor, req["stackName"], str(record.get("eventID") or ""), req))
    out = []
    for at, account, region, actor, stack, event_id, req in updates:
        has_parameters = (isinstance(req.get("parameters"), list)
                          and any(isinstance(p, Mapping) and isinstance(p.get("parameterKey"), str)
                                  for p in req["parameters"]))
        matched_kinds: set[str] = set()
        for before, a, r, writer, kind in writes:
            if kind in matched_kinds:
                continue
            if a != account or r != region or writer == actor or not timedelta(0) <= at - before <= timedelta(hours=1):
                continue
            if kind == "ssm" and not has_parameters:
                continue
            if kind == "s3" and req.get("usePreviousTemplate") is not True:
                continue
            field = ("request.cfn_ssm_overwrite_before_parameterized_update" if kind == "ssm"
                     else "request.cfn_template_object_overwrite_before_update")
            out.append({"cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
                        "event.name": "CloudFormationInputChangedBeforeUpdate", "event.outcome": "success",
                        "event.id": event_id, "event.time": at.isoformat(),
                        "account.id": account, "actor.id": actor, "target.id": stack, field: True})
            matched_kinds.add(kind)
    return out
