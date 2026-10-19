"""IAM administrator grants to groups/roles and user self-group membership."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .aws import _unconditional_admin_grant


def normalize_aws_iam_group_role(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "iam.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"AttachGroupPolicy", "PutGroupPolicy", "AttachRolePolicy", "PutRolePolicy", "AddUserToGroup"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(identity, Mapping):
        return None
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or identity.get("accountId") != account:
        return None
    target = request.get("groupName" if name in {"AttachGroupPolicy", "PutGroupPolicy", "AddUserToGroup"} else "roleName")
    if not isinstance(target, str) or not target:
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    managed_admin = request.get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"
    inline_admin = (isinstance(request.get("policyName"), str) and bool(request["policyName"])
                    and _unconditional_admin_grant(request.get("policyDocument")))
    session = identity.get("sessionContext")
    issuer = session.get("sessionIssuer") if isinstance(session, Mapping) else None
    self_role = (identity.get("type") == "AssumedRole" and isinstance(issuer, Mapping)
                 and issuer.get("userName") == target and isinstance(issuer.get("arn"), str)
                 and issuer["arn"].endswith(f"role/{target}"))
    kind = ("group_attach" if name == "AttachGroupPolicy" and managed_admin else
            "group_inline" if name == "PutGroupPolicy" and inline_admin else
            "role_attach" if name == "AttachRolePolicy" and managed_admin and not self_role else
            "role_inline" if name == "PutRolePolicy" and inline_admin and not self_role else None)
    self_group = (name == "AddUserToGroup" and identity.get("type") == "IAMUser"
                  and isinstance(identity.get("userName"), str)
                  and request.get("userName") == identity["userName"])
    return {
        "cloud.provider": "aws", "event.source": "iam.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": target,
        "request.iam_admin_grant_kind": kind if not failed else None,
        "request.self_user_group_add_accepted": not failed and self_group,
    }
