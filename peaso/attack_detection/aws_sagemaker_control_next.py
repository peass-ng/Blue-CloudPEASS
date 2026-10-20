"""Draft SageMaker control-plane signals, pending live CloudTrail validation.

No request payloads, lifecycle scripts, presigned URLs, or model environment
values are copied into normalized evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any
from urllib.parse import unquote


EVENTS = {
    "CreateNotebookInstance", "CreatePresignedNotebookInstanceUrl",
    "UpdateNotebookInstanceLifecycleConfig", "PutModelPackageGroupPolicy",
    "CreateModelPackage", "DescribeModel",
}


def _field(value: object, key: str) -> object:
    if not isinstance(value, Mapping):
        return None
    wanted = "".join(char for char in key.lower() if char.isalnum())
    for candidate, item in value.items():
        if isinstance(candidate, str) and "".join(char for char in candidate.lower() if char.isalnum()) == wanted:
            return item
    return None


def _policy(value: object) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or len(value) > 100_000:
        return None
    try:
        decoded = json.loads(unquote(value))
    except (TypeError, ValueError):
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _org_wide_group_policy(value: object, group_arn: str) -> bool:
    document = _policy(value)
    if document is None:
        return False
    statements = document.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list):
        return False
    if any(isinstance(statement, Mapping) and statement.get("Effect") == "Deny"
           for statement in statements):
        return False
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        if "NotPrincipal" in statement or "NotAction" in statement:
            continue
        condition = statement.get("Condition")
        if not isinstance(condition, Mapping) or set(condition) != {"StringEquals"}:
            continue
        equals = condition["StringEquals"]
        if (not isinstance(equals, Mapping) or set(equals) != {"aws:PrincipalOrgID"}
                or not isinstance(equals["aws:PrincipalOrgID"], str)
                or re.fullmatch(r"o-[a-z0-9]{10,32}", equals["aws:PrincipalOrgID"]) is None):
            continue
        principal = statement.get("Principal")
        if principal != "*" and principal != {"AWS": "*"}:
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (isinstance(actions, list) and any(action in {
                "sagemaker:DescribeModelPackageGroup", "sagemaker:DescribeModelPackage",
                "sagemaker:ListModelPackages", "sagemaker:*", "*"} for action in actions)
                and isinstance(resources, list) and group_arn in resources):
            return True
    return False


def normalize_aws_sagemaker_control(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if record.get("eventSource") != "sagemaker.amazonaws.com" or name not in EVENTS:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None
            or not isinstance(region, str) or re.fullmatch(r"[a-z0-9-]{3,30}", region) is None):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    notebook = _field(request, "NotebookInstanceName")
    config = _field(request, "NotebookInstanceLifecycleConfigName")
    group = _field(request, "ModelPackageGroupName")
    model = _field(request, "ModelName")
    valid_name = lambda value: isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", value) is not None
    notebook_arn = f"arn:aws:sagemaker:{region}:{account}:notebook-instance/{notebook}"
    group_arn = f"arn:aws:sagemaker:{region}:{account}:model-package-group/{group}"
    role_arn = _field(request, "RoleArn")
    expected_role_prefix = f"arn:aws:iam::{account}:role/"
    notebook_pass = (name == "CreateNotebookInstance" and valid_name(notebook)
        and isinstance(role_arn, str) and role_arn.startswith(expected_role_prefix)
        and isinstance(response, Mapping)
        and _field(response, "NotebookInstanceArn") == notebook_arn)
    presign = (name == "CreatePresignedNotebookInstanceUrl" and valid_name(notebook))
    on_start = _field(request, "OnStart")
    lifecycle = (name == "UpdateNotebookInstanceLifecycleConfig" and valid_name(config)
        and isinstance(on_start, list) and len(on_start) == 1
        and isinstance(on_start[0], Mapping) and bool(_field(on_start[0], "Content")))
    org_wide_policy = (name == "PutModelPackageGroupPolicy" and valid_name(group)
        and _org_wide_group_policy(_field(request, "ResourcePolicy"), group_arn))
    package_arn = _field(response, "ModelPackageArn")
    approved = (name == "CreateModelPackage" and valid_name(group)
        and _field(request, "ModelApprovalStatus") == "Approved"
        and isinstance(package_arn, str)
        and package_arn.startswith(f"arn:aws:sagemaker:{region}:{account}:model-package/{group}/"))
    model_read = name == "DescribeModel" and valid_name(model)
    target = (notebook_arn if valid_name(notebook) and name in {"CreateNotebookInstance", "CreatePresignedNotebookInstanceUrl"}
        else group_arn if valid_name(group) and name in {"PutModelPackageGroupPolicy", "CreateModelPackage"}
        else f"arn:aws:sagemaker:{region}:{account}:notebook-instance-lifecycle-config/{config}" if valid_name(config) and name == "UpdateNotebookInstanceLifecycleConfig"
        else f"arn:aws:sagemaker:{region}:{account}:model/{model}" if valid_name(model) and name == "DescribeModel"
        else None)
    return {"cloud.provider": "aws", "event.source": "sagemaker.amazonaws.com",
            "event.name": name, "event.outcome": "failure" if failed else "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
            "request.sagemaker_notebook_role_passed": not failed and notebook_pass,
            "request.sagemaker_notebook_url_presigned": not failed and presign,
            "request.sagemaker_lifecycle_script_changed": not failed and lifecycle,
            "request.sagemaker_model_group_org_wide_policy": not failed and org_wide_policy,
            "request.sagemaker_model_package_approved": not failed and approved,
            "request.sagemaker_model_config_described": not failed and model_read}
