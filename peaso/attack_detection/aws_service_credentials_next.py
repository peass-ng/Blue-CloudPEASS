"""Service-specific credential creation and reset for another IAM user."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


SERVICES = {"codecommit.amazonaws.com", "cassandra.amazonaws.com"}


def normalize_aws_service_credentials(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "iam.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"CreateServiceSpecificCredential", "ResetServiceSpecificCredential"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response, identity = (record.get("requestParameters"), record.get("responseElements"),
                                   record.get("userIdentity"))
    if not all(isinstance(x, Mapping) for x in (request, response, identity)):
        return None
    target, actor = request.get("userName"), identity.get("userName")
    account = record.get("recipientAccountId")
    credential = response.get("serviceSpecificCredential")
    if (not isinstance(target, str) or not target or not isinstance(actor, str) or not actor
            or target == actor or identity.get("type") != "IAMUser"
            or not isinstance(account, str) or identity.get("accountId") != account
            or not isinstance(credential, Mapping) or credential.get("userName") != target
            or credential.get("status") != "Active"):
        return None
    service = credential.get("serviceName")
    cred_id = credential.get("serviceSpecificCredentialId")
    if (service not in SERVICES or not isinstance(cred_id, str)
            or re.fullmatch(r"[A-Za-z0-9_]{20,128}", cred_id) is None):
        return None
    if (name == "CreateServiceSpecificCredential" and request.get("serviceName") != service
            or name == "ResetServiceSpecificCredential" and request.get("serviceSpecificCredentialId") != cred_id):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "iam.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": f"iam-user:{account}:{target}",
        "request.service_name": service,
        "request.other_user_service_credential_created": not failed and name == "CreateServiceSpecificCredential",
        "request.other_user_service_credential_reset": not failed and name == "ResetServiceSpecificCredential",
    }
