"""CloudFormation stack or change set with a passed role and IAM capability."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def normalize_aws_cloudformation_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if (record.get("eventSource") != "cloudformation.amazonaws.com"
            or record.get("eventName") not in {"CreateStack", "CreateChangeSet"}
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    account = record.get("recipientAccountId")
    name = record["eventName"]
    stack, role = request.get("stackName"), request.get("roleARN")
    result_id = response.get("stackId" if name == "CreateStack" else "id")
    if not all(isinstance(x, str) and x for x in (account, stack, role, result_id)):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    capability = request.get("capabilities")
    accepted = (role.startswith(f"arn:aws:iam::{account}:role/")
                and result_id.startswith("arn:aws:cloudformation:")
                and isinstance(capability, list)
                and any(c in {"CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"} for c in capability))
    if name == "CreateStack":
        accepted = accepted and f":{account}:stack/{stack}/" in result_id
    else:
        change_set = request.get("changeSetName")
        accepted = (accepted and isinstance(change_set, str) and bool(change_set)
                    and f":{account}:changeSet/{change_set}/" in result_id)
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "cloudformation.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": result_id,
        "request.stack_service_role_iam_capability": not failed and accepted and name == "CreateStack",
        "request.change_set_service_role_iam_capability": not failed and accepted and name == "CreateChangeSet",
    }
