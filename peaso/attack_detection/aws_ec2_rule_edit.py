"""Normalize in-place EC2 security group rule edits to public remote access."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from .aws_security_controls import _arn, _event_time


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+\Z")
_GROUP = re.compile(r"sg-[0-9a-f]{8}(?:[0-9a-f]{9})?\Z")
_RULE = re.compile(r"sgr-[0-9a-f]{8}(?:[0-9a-f]{9})?\Z")


def normalize_aws_ec2_rule_edit(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Report an accepted public TCP rule edit without inferring prior CIDR."""
    if (record.get("eventSource") != "ec2.amazonaws.com"
            or record.get("eventName") != "ModifySecurityGroupRules"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping) or not isinstance(identity, Mapping):
        return None
    details = request.get("ModifySecurityGroupRulesRequest")
    result = response.get("ModifySecurityGroupRulesResponse")
    if not isinstance(details, Mapping) or not isinstance(result, Mapping) or result.get("return") is not True:
        return None
    group = details.get("GroupId")
    outer = details.get("SecurityGroupRule")
    rule = outer.get("SecurityGroupRule") if isinstance(outer, Mapping) else None
    rule_id = outer.get("SecurityGroupRuleId") if isinstance(outer, Mapping) else None
    if (not isinstance(group, str) or not _GROUP.fullmatch(group)
            or not isinstance(rule_id, str) or not _RULE.fullmatch(rule_id)
            or not isinstance(rule, Mapping) or rule.get("IpProtocol") != "tcp"
            or rule.get("CidrIpv4") != "0.0.0.0/0"):
        return None
    first, last = rule.get("FromPort"), rule.get("ToPort")
    if type(first) is not int or type(last) is not int or first > last:
        return None
    public_ssh = first <= 22 <= last
    public_rdp = first <= 3389 <= last
    if not (public_ssh or public_rdp):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    actor_arn = identity.get("arn")
    actor = _arn(actor_arn)
    event_id = record.get("eventID")
    event_time = _event_time(record.get("eventTime"))
    try:
        UUID(event_id)
    except (TypeError, ValueError, AttributeError):
        return None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or actor is None or actor[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]
            or event_time is None):
        return None
    return {
        "cloud.provider": "aws", "cloud.region": region,
        "event.source": "ec2.amazonaws.com", "event.name": "ModifySecurityGroupRules",
        "event.outcome": "success", "event.id": event_id, "event.time": event_time,
        "account.id": account, "actor.id": actor_arn, "actor.kind": identity["type"],
        "target.id": f"arn:{actor[1]}:ec2:{region}:{account}:security-group/{group}",
        "request.security_group_rule_id": rule_id,
        "request.existing_rule_set_public_ssh": public_ssh,
        "request.existing_rule_set_public_rdp": public_rdp,
    }
