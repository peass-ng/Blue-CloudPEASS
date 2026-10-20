"""Project IAM certificate/key status and removal requests."""

from collections.abc import Mapping
import re


_ACTIONS = {"UpdateSSHPublicKey", "UpdateSigningCertificate",
            "UpdateServerCertificate", "DeleteSigningCertificate",
            "DeleteVirtualMFADevice"}
_ACCOUNT = re.compile(r"[0-9]{12}")
_NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
_ID = re.compile(r"[A-Z0-9]{16,64}")
_PATH = re.compile(r"/(?:[A-Za-z0-9+=,.@_-]+/)*")


def normalize(event: Mapping) -> dict | None:
    action = event.get("eventName")
    if (action not in _ACTIONS or event.get("eventSource") != "iam.amazonaws.com"
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
    actor = identity.get("arn")
    if (not isinstance(actor, str) or not actor.startswith("arn:")
            or identity.get("accountId") != account
            or not isinstance(event.get("eventID"), str)):
        return None
    if action == "DeleteVirtualMFADevice":
        target = request.get("serialNumber")
        if (not isinstance(target, str)
                or not target.startswith(f"arn:aws:iam::{account}:mfa/")
                or not _NAME.fullmatch(target.rsplit("/", 1)[-1])):
            return None
        kind = "virtualmfa"
    elif action == "UpdateServerCertificate":
        target, path = request.get("serverCertificateName"), request.get("newPath")
        if (not isinstance(target, str) or not _NAME.fullmatch(target)
                or not isinstance(path, str) or not _PATH.fullmatch(path) or path == "/"):
            return None
        kind = "servercertificate"
    else:
        target = request.get("userName")
        if not isinstance(target, str) or not _NAME.fullmatch(target):
            return None
        kind = "user"
        if action == "UpdateSSHPublicKey":
            key_id = request.get("sSHPublicKeyId", request.get("sshPublicKeyId"))
            if (not isinstance(key_id, str) or not key_id.startswith("APKA")
                    or not _ID.fullmatch(key_id) or request.get("status") != "Inactive"):
                return None
        else:
            cert_id = request.get("certificateId")
            if not isinstance(cert_id, str) or not _ID.fullmatch(cert_id):
                return None
            if action == "UpdateSigningCertificate" and request.get("status") != "Inactive":
                return None
    return {"cloud.provider": "aws", "event.source": "iam.amazonaws.com",
            "event.name": action, "event.outcome": "success",
            "event.id": event["eventID"], "event.time": event.get("eventTime"),
            "account.id": account, "cloud.region": "us-east-1",
            "actor.id": actor, "target.type": kind, "target.id": target,
            "request.iam_cert_key_control_observed": True}
