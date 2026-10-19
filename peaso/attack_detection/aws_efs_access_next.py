"""Privileged EFS access point and broad client root policy writes."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


def _root_point(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    user, root = value.get("posixUser"), value.get("rootDirectory")
    return (isinstance(user, Mapping) and user.get("uid") == 0 and user.get("gid") == 0
            and isinstance(root, Mapping) and root.get("path") == "/")


def _wildcard_root_policy(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        policy = json.loads(value)
    except json.JSONDecodeError:
        return False
    statements = policy.get("Statement") if isinstance(policy, Mapping) else None
    statements = [statements] if isinstance(statements, Mapping) else statements
    if not isinstance(statements, list):
        return False
    if any(isinstance(s, Mapping) and s.get("Effect") == "Deny" for s in statements):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition") or "NotAction" in statement or "NotPrincipal" in statement:
            continue
        principal = statement.get("Principal")
        principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
        principal = principal if isinstance(principal, list) else [principal]
        actions = statement.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        if ("*" in principal and "elasticfilesystem:ClientMount" in actions
                and "elasticfilesystem:ClientRootAccess" in actions):
            return True
    return False


def normalize_aws_efs_access(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "elasticfilesystem.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"CreateAccessPoint", "PutFileSystemPolicy"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    fs = request.get("fileSystemId")
    if not isinstance(fs, str) or re.fullmatch(r"fs-[0-9a-f]{8,40}", fs) is None:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    root_point = (name == "CreateAccessPoint" and response.get("fileSystemId") == fs
                  and isinstance(response.get("accessPointId"), str)
                  and _root_point(request) and _root_point(response))
    broad_policy = (name == "PutFileSystemPolicy" and response.get("fileSystemId") == fs
                    and _wildcard_root_policy(request.get("policy"))
                    and _wildcard_root_policy(response.get("policy")))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "elasticfilesystem.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": response.get("accessPointId") if root_point else fs,
        "request.efs_root_access_point": not failed and root_point,
        "request.efs_wildcard_client_root_policy": not failed and broad_policy,
    }


def normalize_aws_efs_deletion(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "elasticfilesystem.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"DeleteFileSystemPolicy", "DeleteAccessPoint", "DeleteFileSystem"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    field = "accessPointId" if name == "DeleteAccessPoint" else "fileSystemId"
    target = request.get(field)
    pattern = r"fsap-[0-9a-f]{8,40}" if field == "accessPointId" else r"fs-[0-9a-f]{8,40}"
    if not isinstance(target, str) or re.fullmatch(pattern, target) is None:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "elasticfilesystem.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": target,
        "request.efs_policy_deleted": not failed and name == "DeleteFileSystemPolicy",
        "request.efs_access_point_deleted": not failed and name == "DeleteAccessPoint",
        "request.efs_file_system_deleted": not failed and name == "DeleteFileSystem",
    }
