"""Accepted EC2 group changes and synthetic custom SSM compliance writes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_INSTANCE = re.compile(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})")
_GROUP = re.compile(r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})")


def normalize_aws_ec2_ssm_batch96(record: Mapping[str, Any]) -> dict[str, Any] | None:
    source, name = record.get("eventSource"), record.get("eventName")
    if not isinstance(source, str) or not isinstance(name, str):
        return None
    if (source, name) not in {
        ("ec2.amazonaws.com", "ModifyInstanceAttribute"),
        ("ssm.amazonaws.com", "PutComplianceItems"),
    }:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    response = record.get("responseElements")
    account = record.get("recipientAccountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    instance_id = request.get("instanceId") if name == "ModifyInstanceAttribute" else request.get("resourceId")
    valid_instance = isinstance(instance_id, str) and _INSTANCE.fullmatch(instance_id) is not None

    groups = request.get("groupSet")
    groups = groups.get("items") if isinstance(groups, Mapping) else None
    valid_groups = (isinstance(groups, list) and bool(groups)
                    and all(isinstance(group, Mapping) and isinstance(group.get("groupId"), str)
                            and _GROUP.fullmatch(group["groupId"]) is not None for group in groups))
    group_set_supplied = (name == "ModifyInstanceAttribute" and not failed and valid_instance
                          and valid_groups and isinstance(response, Mapping)
                          and response.get("_return") is True)

    items = request.get("items")
    custom_compliant = (
        name == "PutComplianceItems" and not failed and valid_instance
        and request.get("resourceType") == "ManagedInstance"
        and isinstance(request.get("complianceType"), str)
        and request["complianceType"].startswith("Custom:")
        and len(request["complianceType"]) > len("Custom:")
        and isinstance(items, list) and bool(items)
        and any(isinstance(item, Mapping) and isinstance(item.get("id"), str)
                and bool(item["id"]) and item.get("status") == "COMPLIANT" for item in items)
    )
    return {
        "cloud.provider": "aws", "event.source": source, "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": instance_id if valid_instance else None,
        "request.instance_security_group_set_supplied": group_set_supplied,
        "request.custom_compliance_marked_compliant": custom_compliant,
    }
