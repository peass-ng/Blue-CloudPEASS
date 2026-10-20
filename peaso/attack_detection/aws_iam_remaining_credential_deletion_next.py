"""Project accepted IAM credential and instance-profile removal routes."""

from collections.abc import Mapping
import re


_TARGETS = {
    "DeleteLoginProfile": "userName",
    "DeleteServiceSpecificCredential": "userName",
    "RemoveRoleFromInstanceProfile": "instanceProfileName",
    "DeleteInstanceProfile": "instanceProfileName",
    "DeleteServerCertificate": "serverCertificateName",
}
_NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
_ACCOUNT = re.compile(r"[0-9]{12}")
_SERVICE_CREDENTIAL_ID = re.compile(r"[A-Z0-9]{16,64}")


def normalize(event: Mapping) -> dict | None:
    action = event.get("eventName")
    if (action not in _TARGETS or event.get("eventSource") != "iam.amazonaws.com"
            or event.get("eventCategory") != "Management"
            or event.get("eventType") != "AwsApiCall"
            or event.get("managementEvent") is not True
            or event.get("readOnly") is not False
            or event.get("awsRegion") != "us-east-1"
            or event.get("errorCode") or event.get("errorMessage")):
        return None
    account, request, identity = (event.get("recipientAccountId"),
                                  event.get("requestParameters"), event.get("userIdentity"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)):
        return None
    target, actor = request.get(_TARGETS[action]), identity.get("arn")
    if (not isinstance(target, str) or not _NAME.fullmatch(target)
            or not isinstance(actor, str) or not actor.startswith("arn:")
            or identity.get("accountId") != account
            or not isinstance(event.get("eventID"), str)):
        return None
    if action == "DeleteServiceSpecificCredential":
        credential_id = request.get("serviceSpecificCredentialId")
        if (not isinstance(credential_id, str)
                or not _SERVICE_CREDENTIAL_ID.fullmatch(credential_id)):
            return None
    if action == "RemoveRoleFromInstanceProfile":
        role = request.get("roleName")
        if not isinstance(role, str) or not _NAME.fullmatch(role):
            return None
    kind = "user" if _TARGETS[action] == "userName" else (
        "instanceprofile" if _TARGETS[action] == "instanceProfileName" else "servercertificate")
    return {"cloud.provider": "aws", "event.source": "iam.amazonaws.com",
            "event.name": action, "event.outcome": "success",
            "event.id": event["eventID"], "event.time": event.get("eventTime"),
            "account.id": account, "cloud.region": "us-east-1",
            "actor.id": actor, "target.type": kind, "target.id": target,
            "request.iam_credential_deletion_observed": True}
