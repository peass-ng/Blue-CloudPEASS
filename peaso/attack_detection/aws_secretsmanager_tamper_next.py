"""Changes to a secret's current version and resource policy."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_secret_tamper(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "secretsmanager.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateSecretVersionStage", "DeleteResourcePolicy", "DeleteSecret",
                    "RotateSecret", "StopReplicationToReplica"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    arn = request.get("secretId")
    account = record.get("recipientAccountId")
    if (not isinstance(arn, str) or not isinstance(account, str)
            or f":{account}:secret:" not in arn or response.get("arn") != arn):
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    moved = (name == "UpdateSecretVersionStage" and request.get("versionStage") == "AWSCURRENT"
             and isinstance(request.get("moveToVersionId"), str)
             and isinstance(request.get("removeFromVersionId"), str)
             and request["moveToVersionId"] != request["removeFromVersionId"])
    rotation_lambda = request.get("rotationLambdaARN")
    bound = (name == "RotateSecret" and isinstance(rotation_lambda, str)
             and re.fullmatch(r"arn:aws:lambda:[a-z0-9-]+:\d{12}:function:[A-Za-z0-9_-]+", rotation_lambda)
             is not None)
    return {
        "cloud.provider": "aws", "event.source": "secretsmanager.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": arn,
        "request.secretsmanager_current_version_moved": not failed and moved,
        "request.secretsmanager_resource_policy_deleted": not failed and name == "DeleteResourcePolicy",
        "request.secret_force_delete_accepted": (
            not failed and name == "DeleteSecret" and request.get("forceDeleteWithoutRecovery") is True
        ),
        "request.secretsmanager_rotation_lambda_bound": not failed and bound,
        "request.secretsmanager_replica_promoted": not failed and name == "StopReplicationToReplica",
    }
