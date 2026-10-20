"""Project IAM credential, boundary, policy-version and path API calls."""

from collections.abc import Mapping
import re

from .aws_keyspaces_next import normalize_keyspaces_other_user_credential
from .aws_service_credentials_next import normalize_aws_service_credentials


CONFIG = {
    "SetDefaultPolicyVersion": ("policyArn", "versionId", "aws-tech-ea2d8bcb51ab535d", 44),
    "CreateAccessKey": ("userName", None, "aws-tech-778af313336582aa", 72),
    "DeleteAccessKey": ("userName", "accessKeyId", "aws-tech-f4cc1e45d2f1fc5e", 321),
    "CreateServiceSpecificCredential": ("userName", "serviceName", "aws-tech-33d5f1d347563a1b", 155),
    "ResetServiceSpecificCredential": ("userName", "serviceSpecificCredentialId", "aws-tech-33d5f1d347563a1b", 155),
    "PutUserPermissionsBoundary": ("userName", "permissionsBoundary", "aws-tech-bc53ab276e1fb32f", 772),
    "PutRolePermissionsBoundary": ("roleName", "permissionsBoundary", "aws-tech-2b507d4503a061cf", 815),
    "UpdateUser": ("userName", "newPath", "aws-tech-00bcdcaeb764e03b", 947),
    "UpdateGroup": ("groupName", "newPath", "aws-tech-00bcdcaeb764e03b", 947),
}
NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
POLICY_ARN = re.compile(r"arn:aws(?:-[a-z]+)?:iam::(?:\d{12}|aws):policy/[\w+=,.@/-]+")
KEY_ID = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
SERVICE_CREDENTIAL_ID = re.compile(r"[A-Z0-9]{16,64}")
SERVICE_NAME = re.compile(r"[a-z0-9.-]+\.amazonaws\.com")
PATH = re.compile(r"/(?:[A-Za-z0-9+=,.@_-]+/)*")


def field(request: Mapping, name: str):
    expected = re.sub(r"[^a-z0-9]", "", name.lower())
    for key, value in request.items():
        if isinstance(key, str) and re.sub(r"[^a-z0-9]", "", key.lower()) == expected:
            return value
    return None


def normalize(event: Mapping) -> dict | None:
    action = event.get("eventName")
    if (action not in CONFIG or event.get("eventSource") != "iam.amazonaws.com"
            or event.get("eventCategory") != "Management" or event.get("eventType") != "AwsApiCall"
            or event.get("managementEvent") is not True or event.get("awsRegion") != "us-east-1"):
        return None
    if action in {"CreateServiceSpecificCredential", "ResetServiceSpecificCredential"} and (
        normalize_keyspaces_other_user_credential(event) is not None
        or normalize_aws_service_credentials(event) is not None
    ):
        return None
    account = event.get("recipientAccountId")
    request = event.get("requestParameters")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account) or not isinstance(request, Mapping):
        return None
    target_key, detail_key, _, _ = CONFIG[action]
    target, detail = field(request, target_key), field(request, detail_key) if detail_key else None
    if not isinstance(target, str) or not isinstance(detail, str) and detail_key:
        return None
    if target_key in {"userName", "roleName", "groupName"}:
        if not NAME.fullmatch(target):
            return None
    elif not POLICY_ARN.fullmatch(target) or f"::{account}:policy/" not in target:
        return None
    if detail_key == "versionId" and not re.fullmatch(r"v[1-9][0-9]*", detail):
        return None
    if detail_key == "accessKeyId" and not KEY_ID.fullmatch(detail):
        return None
    if detail_key == "serviceName" and not SERVICE_NAME.fullmatch(detail):
        return None
    if detail_key == "serviceSpecificCredentialId" and not SERVICE_CREDENTIAL_ID.fullmatch(detail):
        return None
    if detail_key == "permissionsBoundary" and (not POLICY_ARN.fullmatch(detail) or
        not (f"::{account}:policy/" in detail or "::aws:policy/" in detail)):
        return None
    if detail_key == "newPath" and (not PATH.fullmatch(detail) or detail == "/"):
        return None
    success = not (event.get("errorCode") or event.get("errorMessage"))
    identity = event.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    kind = "policy" if target_key == "policyArn" else target_key[:-4].lower()
    return {
        "cloud.provider": "aws", "event.source": "iam.amazonaws.com",
        "event.name": action, "event.outcome": "success" if success else "failure",
        "event.id": event.get("eventID"), "event.time": event.get("eventTime"),
        "account.id": account, "cloud.region": "us-east-1",
        "actor.id": actor if isinstance(actor, str) else None,
        "target.type": kind, "target.id": target,
        "request.iam_credential_boundary_action_observed": success,
        "request.iam_credential_boundary_action": action,
        "request.detail_id": detail,
    }
