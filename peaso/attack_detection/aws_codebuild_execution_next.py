"""Project CodeBuild execution and project rewrite management events.

Its output is a precursor signal; a successful API call alone does not prove a
privileged build effect.
Never emit buildspecs, environment variable names/values or source URLs.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_OPERATIONS = {"StartBuild", "StartBuildBatch", "RetryBuild", "UpdateProject", "CreateProject"}
_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-\d\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,149}\Z")
_BUILD_ID = re.compile(r"([A-Za-z0-9][A-Za-z0-9_-]{0,149}):[0-9a-fA-F-]{36}\Z")


def _project_name(value: Any, partition: str, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    if _NAME.fullmatch(value):
        return value
    prefix = f"arn:{partition}:codebuild:{region}:{account}:project/"
    if value.startswith(prefix) and _NAME.fullmatch(value[len(prefix):]):
        return value[len(prefix):]
    return None


def normalize_codebuild_execution(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a secret-free single-event projection for five write APIs."""
    if record.get("eventSource") != "codebuild.amazonaws.com":
        return None
    operation = record.get("eventName")
    if operation not in _OPERATIONS:
        return None
    if (record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    identity = record.get("userIdentity")
    if not isinstance(identity, Mapping):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor = identity.get("arn")
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(actor, str) or not actor.startswith("arn:")):
        return None
    if identity.get("accountId") not in (None, account):
        return None
    partition = "aws-us-gov" if region.startswith("us-gov-") else (
        "aws-cn" if region.startswith("cn-") else "aws"
    )

    if operation == "RetryBuild":
        build_id = request.get("id")
        match = _BUILD_ID.fullmatch(build_id) if isinstance(build_id, str) else None
        project_name = match.group(1) if match else None
    else:
        project_name = _project_name(
            request.get("name" if operation in {"UpdateProject", "CreateProject"}
                        else "projectName"),
            partition,
            region,
            account,
        )
        build_id = None
    if project_name is None:
        return None

    response = record.get("responseElements")
    if response is not None and not isinstance(response, Mapping):
        return None
    response = response or {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    result = response.get("buildBatch" if operation == "StartBuildBatch" else
                          "project" if operation in {"UpdateProject", "CreateProject"}
                          else "build")
    result = result if isinstance(result, Mapping) else {}
    result_id = result.get("id")
    if not isinstance(result_id, str):
        result_id = None
    if result_id is not None and operation not in {"UpdateProject", "CreateProject"}:
        result_match = _BUILD_ID.fullmatch(result_id)
        if result_match is None or result_match.group(1) != project_name:
            return None
    if operation == "RetryBuild" and result_id == build_id:
        return None

    return {
        "cloud.provider": "aws",
        "event.source": "codebuild.amazonaws.com",
        "event.name": operation,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": actor,
        "target.id": f"arn:{partition}:codebuild:{region}:{account}:project/{project_name}",
        "request.codebuild_buildspec_override_present": (
            operation in {"StartBuild", "StartBuildBatch"}
            and "buildspecOverride" in request
            and request["buildspecOverride"] not in (None, "")
        ),
        "request.codebuild_environment_override_present": (
            operation in {"StartBuild", "StartBuildBatch"}
            and isinstance(request.get("environmentVariablesOverride"), list)
            and bool(request["environmentVariablesOverride"])
        ),
        "request.codebuild_service_role_supplied": (
            operation in {"UpdateProject", "CreateProject"}
            and isinstance(request.get("serviceRole"), str)
            and bool(request["serviceRole"])
        ),
        "request.codebuild_project_definition_supplied": (
            operation in {"UpdateProject", "CreateProject"}
            and any(key in request for key in ("source", "environment", "artifacts"))
        ),
        "response.codebuild_project_observed": (
            operation in {"UpdateProject", "CreateProject"}
            and result.get("name") == project_name
        ),
        "request.codebuild_retry": operation == "RetryBuild",
        "response.codebuild_build_id_observed": result_id is not None,
    }
