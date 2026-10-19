"""CodeBuild control plane events with a directly observed security effect."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_codebuild_change(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "codebuild.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateProjectVisibility", "DeleteProject", "DeleteSourceCredentials"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    target = (request.get("projectArn") if name == "UpdateProjectVisibility"
              else request.get("name") if name == "DeleteProject"
              else request.get("arn"))
    if not isinstance(target, str) or not target:
        return None
    response = record.get("responseElements")
    response = response if isinstance(response, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    account = record.get("recipientAccountId") or identity.get("accountId")
    region = record.get("awsRegion")
    resource = "token/[a-z0-9_-]+" if name == "DeleteSourceCredentials" else "project/[A-Za-z0-9_-]+"
    if (not isinstance(account, str) or not re.fullmatch(r"\d{12}", account)
            or not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region)
            or not re.fullmatch(
                rf"arn:aws(?:-us-gov|-cn)?:codebuild:{re.escape(region)}:{account}:{resource}",
                target,
            )):
        return None
    return {
        "cloud.provider": "aws",
        "event.source": "codebuild.amazonaws.com",
        "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"),
        "event.time": record.get("eventTime"),
        "account.id": account,
        "actor.id": identity.get("arn"),
        "target.id": target,
        "request.codebuild_public_visibility": (
            name == "UpdateProjectVisibility"
            and not failed
            and request.get("projectVisibility") == "PUBLIC_READ"
        ),
        "request.codebuild_project_deleted": name == "DeleteProject" and not failed,
        "request.codebuild_source_credential_deleted": (
            name == "DeleteSourceCredentials" and not failed and response.get("arn") == target
        ),
    }
