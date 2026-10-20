"""Isolated CodeBuild sandbox, tag and project/build-read CloudTrail signals.

Projection retains action metadata only. Session tokens, commands, tag values,
project environment values, source URLs and build outputs are never emitted.
"""

from collections.abc import Mapping
import re
from typing import Any


NAMES = {"StartCommandExecution", "StartSandboxConnection", "UpdateProject",
         "BatchGetProjects", "BatchGetBuilds"}
REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]")
PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,149}")
SANDBOX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,149}:[0-9a-fA-F-]{36}")
BUILD = SANDBOX


def _partition(region: str) -> str:
    return "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"


def _sandbox_id(value: Any, partition: str, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:{partition}:codebuild:{region}:{account}:sandbox/"
    if value.startswith(prefix):
        value = value[len(prefix):]
    return value if SANDBOX.fullmatch(value) else None


def _project(value: Any, partition: str, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:{partition}:codebuild:{region}:{account}:project/"
    if value.startswith(prefix):
        value = value[len(prefix):]
    return value if PROJECT.fullmatch(value) else None


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "codebuild.amazonaws.com" or name not in NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name in {"StartSandboxConnection", "BatchGetProjects", "BatchGetBuilds"})
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region, request = (record.get("recipientAccountId"), record.get("awsRegion"),
                                record.get("requestParameters"))
    identity = record.get("userIdentity")
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or not isinstance(region, str) or not REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)):
        return None
    partition = _partition(region)
    target = f"arn:{partition}:codebuild:{region}:{account}:project/*"
    if name in {"StartCommandExecution", "StartSandboxConnection"}:
        sandbox = _sandbox_id(request.get("sandboxId"), partition, region, account)
        if sandbox is None:
            return None
        if name == "StartCommandExecution" and not isinstance(request.get("command"), str):
            return None
        target = f"arn:{partition}:codebuild:{region}:{account}:sandbox/{sandbox}"
    elif name == "UpdateProject":
        project = _project(request.get("name"), partition, region, account)
        if project is None or "tags" not in request or request["tags"] in (None, [], ""):
            return None
        target = f"arn:{partition}:codebuild:{region}:{account}:project/{project}"
        response = record.get("responseElements")
        response_project = response.get("project") if isinstance(response, Mapping) else None
        if isinstance(response_project, Mapping) and "name" in response_project and response_project["name"] != project:
            return None
    elif name == "BatchGetProjects":
        names = request.get("names")
        if (not isinstance(names, list) or not 1 <= len(names) <= 100
                or any(_project(item, partition, region, account) is None for item in names)):
            return None
        response = record.get("responseElements")
        if isinstance(response, Mapping) and "projects" in response:
            projects = response["projects"]
            if not isinstance(projects, list) or not projects:
                return None
    else:
        ids = request.get("ids")
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 100
                or any(not isinstance(item, str) or not BUILD.fullmatch(item) for item in ids)):
            return None
        response = record.get("responseElements")
        if isinstance(response, Mapping) and "builds" in response:
            builds = response["builds"]
            if not isinstance(builds, list) or not builds:
                return None
    flags = {"StartCommandExecution": "sandbox_command_started",
             "StartSandboxConnection": "sandbox_connection_started",
             "UpdateProject": "project_tags_submitted",
             "BatchGetProjects": "project_configuration_read",
             "BatchGetBuilds": "build_configuration_read"}
    return {"cloud.provider": "aws", "event.source": "codebuild.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity["arn"], "target.id": target,
            "request.codebuild_" + flags[name]: True}
