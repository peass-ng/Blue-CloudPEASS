"""EC2 metadata, security-group ingress, and GuardDuty scan-exclusion changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def _items(value: Any) -> list[Mapping[str, Any]]:
    items = value.get("items") if isinstance(value, Mapping) else None
    return [x for x in items if isinstance(x, Mapping)] if isinstance(items, list) else []


def normalize_aws_ec2_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "ec2.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules",
                    "ModifyInstanceMetadataOptions", "CreateTags"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request, response = record.get("requestParameters"), record.get("responseElements")
    if not isinstance(request, Mapping) or not isinstance(response, Mapping):
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or response.get("errorCode") or response.get("errorMessage"))
    account = record.get("recipientAccountId")
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}

    permissions = _items(request.get("ipPermissions"))
    ssh = any(p.get("ipProtocol") == "tcp" and p.get("fromPort") == 22 and p.get("toPort") == 22
              and any(r.get("cidrIp") == "0.0.0.0/0" for r in _items(p.get("ipRanges")))
              for p in permissions)
    rule_set = response.get("securityGroupRuleSet")
    ingress_returned = any(r.get("groupId") == request.get("groupId")
                           and r.get("groupOwnerId") == account and r.get("isEgress") is False
                           and r.get("ipProtocol") == "tcp" and r.get("fromPort") == 22
                           and r.get("toPort") == 22 and r.get("cidrIpv4") == "0.0.0.0/0"
                           for r in _items(rule_set))

    metadata = request.get("ModifyInstanceMetadataOptionsRequest")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    metadata_response = response.get("ModifyInstanceMetadataOptionsResponse")
    metadata_response = metadata_response if isinstance(metadata_response, Mapping) else {}
    options = metadata_response.get("instanceMetadataOptions")
    options = options if isinstance(options, Mapping) else {}
    same_instance = (isinstance(metadata.get("InstanceId"), str)
                     and re.fullmatch(r"i-[0-9a-f]+", metadata["InstanceId"]) is not None
                     and metadata_response.get("instanceId") == metadata["InstanceId"])

    edit = request.get("ModifySecurityGroupRulesRequest")
    edit = edit if isinstance(edit, Mapping) else {}
    outer = edit.get("SecurityGroupRule")
    outer = outer if isinstance(outer, Mapping) else {}
    inner = outer.get("SecurityGroupRule")
    inner = inner if isinstance(inner, Mapping) else {}
    edit_response = response.get("ModifySecurityGroupRulesResponse")
    edit_ok = (isinstance(edit_response, Mapping) and edit_response.get("return") is True
               and isinstance(edit.get("GroupId"), str) and re.fullmatch(r"sg-[0-9a-f]+", edit["GroupId"])
               and isinstance(outer.get("SecurityGroupRuleId"), str)
               and re.fullmatch(r"sgr-[0-9a-f]+", outer["SecurityGroupRuleId"]))
    edit_public = edit_ok and inner.get("IpProtocol") == "tcp" and inner.get("CidrIpv4") == "0.0.0.0/0"

    resources = _items(request.get("resourcesSet"))
    tags = _items(request.get("tagSet"))
    ebs_excluded = (response.get("_return") is True
                    and any(isinstance(r.get("resourceId"), str)
                            and re.fullmatch(r"vol-[0-9a-f]+", r["resourceId"]) for r in resources)
                    and any(t.get("key") == "GuardDutyExcluded" and t.get("value") == "true" for t in tags))
    return {
        "cloud.provider": "aws", "event.source": "ec2.amazonaws.com", "event.name": name,
        "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": request.get("groupId") or metadata.get("InstanceId") or edit.get("GroupId"),
        "request.public_ssh_ingress": (
            not failed and name == "AuthorizeSecurityGroupIngress" and ssh
            and response.get("_return") is True and ingress_returned
        ),
        "request.imdsv1_allowed": (
            not failed and name == "ModifyInstanceMetadataOptions" and same_instance
            and metadata.get("HttpTokens") == "optional" and options.get("httpTokens") == "optional"
        ),
        "request.metadata_hop_limit_at_least_two": (
            not failed and name == "ModifyInstanceMetadataOptions" and same_instance
            and type(metadata.get("HttpPutResponseHopLimit")) is int
            and metadata["HttpPutResponseHopLimit"] >= 2
            and type(options.get("httpPutResponseHopLimit")) is int
            and options["httpPutResponseHopLimit"] >= 2
        ),
        "request.existing_rule_set_public_ssh": (
            not failed and name == "ModifySecurityGroupRules" and edit_public
            and inner.get("FromPort") == 22 and inner.get("ToPort") == 22
        ),
        "request.existing_rule_set_public_rdp": (
            not failed and name == "ModifySecurityGroupRules" and edit_public
            and inner.get("FromPort") == 3389 and inner.get("ToPort") == 3389
        ),
        "request.guardduty_ebs_scan_exclusion_tag_set": not failed and name == "CreateTags" and ebs_excluded,
    }
