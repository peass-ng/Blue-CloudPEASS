"""Conservative IoT Core management signals observed in an owned AWS lab.

IoT device data plane activity and credential vending are absent from CloudTrail.
The normalizer does not infer topic SQL, policy grants, tunnel traffic, or
credential contents from management events that omit them.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_NAME = re.compile(r"[A-Za-z0-9_=@-]{1,128}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-\d\Z")
_TUNNEL = re.compile(r"[A-Za-z0-9_+=:-]{1,128}\Z")


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    source = record.get("eventSource")
    if not isinstance(name, str) or not isinstance(source, str):
        return None
    if (source, name) not in {
        ("iot.amazonaws.com", "CreateRoleAlias"),
        ("iot.amazonaws.com", "UpdateRoleAlias"),
        ("iot.amazonaws.com", "CreateTopicRule"),
        ("iotsecuredtunneling.amazonaws.com", "OpenTunnel"),
        ("iotsecuredtunneling.amazonaws.com", "RotateTunnelAccessToken"),
    }:
        return None
    if (record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    identity = record.get("userIdentity")
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str)
            or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None

    flags: dict[str, bool] = {}
    target = None
    if name in {"CreateRoleAlias", "UpdateRoleAlias"}:
        alias, role = request.get("roleAlias"), request.get("roleArn")
        if (not isinstance(alias, str) or not _NAME.fullmatch(alias)
                or not isinstance(role, str)
                or not role.startswith(f"arn:aws:iam::{account}:role/")
                or not isinstance(response, Mapping)
                or response.get("roleAlias") != alias
                or response.get("roleAliasArn")
                   != f"arn:aws:iot:{region}:{account}:rolealias/{alias}"):
            return None
        target = response["roleAliasArn"]
        flags["request.iot_role_alias_created" if name == "CreateRoleAlias"
              else "request.iot_role_alias_repointed"] = True
    elif name == "CreateTopicRule":
        rule = request.get("ruleName")
        if not isinstance(rule, str) or not _NAME.fullmatch(rule):
            return None
        # CloudTrail logged ruleName only in the real accepted event. The
        # wildcard SQL, action target and passed role require inventory.
        target = f"arn:aws:iot:{region}:{account}:rule/{rule}"
        flags["request.iot_topic_rule_created"] = True
    elif name == "OpenTunnel":
        if not isinstance(response, Mapping):
            return None
        tunnel_id, arn = response.get("tunnelId"), response.get("tunnelArn")
        if (not isinstance(tunnel_id, str) or not _TUNNEL.fullmatch(tunnel_id)
                or arn != f"arn:aws:iot:{region}:{account}:tunnel/{tunnel_id}"):
            return None
        target = arn
        flags["request.iot_tunnel_opened"] = True
    else:
        tunnel_id = request.get("tunnelId")
        mode = request.get("clientMode")
        if (not isinstance(tunnel_id, str) or not _TUNNEL.fullmatch(tunnel_id)
                or mode not in {"SOURCE", "ALL"}
                or not isinstance(response, Mapping)
                or response.get("tunnelArn")
                   != f"arn:aws:iot:{region}:{account}:tunnel/{tunnel_id}"):
            return None
        target = response["tunnelArn"]
        flags["request.iot_tunnel_source_token_rotated"] = True

    return {
        "cloud.provider": "aws", "event.source": source,
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity["arn"],
        "target.id": target, **flags,
    }
