"""Project accepted IAM credential and identity removals with named targets."""

from collections.abc import Mapping
import re


_TARGETS = {
    "DeleteSSHPublicKey": "userName",
    "RemoveUserFromGroup": "userName",
    "DeleteUser": "userName",
    "DeleteRole": "roleName",
    "DeleteGroup": "groupName",
}
_NAME = re.compile(r"[\w+=,.@-]{1,128}", re.ASCII)
_ACCOUNT = re.compile(r"[0-9]{12}")


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
    target = request.get(_TARGETS[action])
    actor = identity.get("arn")
    if (not isinstance(target, str) or not _NAME.fullmatch(target)
            or not isinstance(actor, str) or not actor.startswith("arn:")
            or identity.get("accountId") != account
            or not isinstance(event.get("eventID"), str)):
        return None
    if action == "DeleteSSHPublicKey":
        ssh_id = request.get("sSHPublicKeyId", request.get("sshPublicKeyId"))
        if not isinstance(ssh_id, str) or not re.fullmatch(r"APKA[A-Z0-9]{16}", ssh_id):
            return None
    if action == "RemoveUserFromGroup":
        group = request.get("groupName")
        if not isinstance(group, str) or not _NAME.fullmatch(group):
            return None
    return {"cloud.provider": "aws", "event.source": "iam.amazonaws.com",
            "event.name": action, "event.outcome": "success",
            "event.id": event["eventID"], "event.time": event.get("eventTime"),
            "account.id": account, "cloud.region": "us-east-1",
            "actor.id": actor, "target.type": _TARGETS[action][:-4].lower(),
            "target.id": target, "request.iam_identity_deletion_observed": True}
