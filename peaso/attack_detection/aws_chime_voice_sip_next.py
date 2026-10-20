"""Bounded Chime SDK Voice SIP management signals from CloudTrail."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_CONNECTOR = re.compile(r"[A-Za-z0-9]{10,64}\Z")
_NAMES = {"UpdateVoiceConnector", "CreateSipMediaApplication",
          "UpdateSipMediaApplication", "CreateSipRule", "UpdateSipRule"}


def _endpoints(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, Mapping) and isinstance(item.get("lambdaArn"), str)
                    and (item["lambdaArn"] == "HIDDEN_DUE_TO_SECURITY_REASONS"
                         or item["lambdaArn"].startswith("arn:aws:lambda:")) for item in value))


def _targets(value: Any) -> bool:
    return (isinstance(value, list) and bool(value)
            and all(isinstance(item, Mapping) and isinstance(item.get("sipMediaApplicationId"), str)
                    and _UUID.fullmatch(item["sipMediaApplicationId"])
                    and isinstance(item.get("priority"), int)
                    and not isinstance(item["priority"], bool)
                    and 1 <= item["priority"] <= 25 for item in value))


def normalize_aws_chime_voice_sip(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if (name not in _NAMES or record.get("eventSource") != "chime-sdk-voice.amazonaws.com"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response, identity = (record.get("requestParameters"),
                                   record.get("responseElements"), record.get("userIdentity"))
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str) or not identity["arn"]
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None

    flag = None
    target = None
    expected_target = None
    if name == "UpdateVoiceConnector":
        body = response.get("voiceConnector")
        connector = request.get("voiceConnectorId")
        if (not isinstance(body, Mapping) or not isinstance(connector, str)
                or not _CONNECTOR.fullmatch(connector)
                or body.get("voiceConnectorId") != connector
                or request.get("requireEncryption") is not False
                or body.get("requireEncryption") is not False):
            return None
        flag = "request.chime_voice_encryption_requirement_disabled"
        target = body.get("voiceConnectorArn")
        expected_target = f"arn:aws:chime:{region}:{account}:vc/{connector}"
    elif name in {"CreateSipMediaApplication", "UpdateSipMediaApplication"}:
        body = response.get("sipMediaApplication")
        if (not isinstance(body, Mapping) or not _endpoints(request.get("endpoints"))
                or body.get("endpoints") != request["endpoints"]
                or not isinstance(body.get("sipMediaApplicationId"), str)
                or not _UUID.fullmatch(body["sipMediaApplicationId"])):
            return None
        if name == "UpdateSipMediaApplication":
            if request.get("sipMediaApplicationId") != body["sipMediaApplicationId"]:
                return None
            flag = "request.chime_sip_application_endpoint_updated"
        else:
            if request.get("awsRegion") != region:
                return None
            flag = "request.chime_sip_application_endpoint_configured"
        target = body.get("sipMediaApplicationArn")
        expected_target = (f"arn:aws:chime:{region}:{account}:sma/"
                           f"{body['sipMediaApplicationId']}")
    else:
        body = response.get("sipRule")
        if (not isinstance(body, Mapping)
                or not isinstance(body.get("sipRuleId"), str)
                or not _UUID.fullmatch(body["sipRuleId"])
                or not _targets(request.get("targetApplications"))
                or body.get("targetApplications") != request["targetApplications"]):
            return None
        if name == "CreateSipRule":
            if (request.get("triggerType") not in {"RequestUriHostname", "ToPhoneNumber"}
                    or not isinstance(request.get("triggerValue"), str)
                    or not request["triggerValue"]
                    or body.get("triggerType") != request["triggerType"]
                    or body.get("triggerValue") != request["triggerValue"]
                    or body.get("disabled") is not request.get("disabled")):
                return None
            flag = "request.chime_sip_rule_target_created"
        else:
            if (request.get("sipRuleId") != body["sipRuleId"]
                    or request.get("disabled") is not False
                    or body.get("disabled") is not False):
                return None
            flag = "request.chime_sip_rule_target_enabled"
        target = body.get("sipRuleArn")
        expected_target = f"arn:aws:chime::{account}:sip-rule/{body['sipRuleId']}"

    if target != expected_target:
        return None
    return {"cloud.provider": "aws", "event.source": "chime-sdk-voice.amazonaws.com",
            "event.name": name, "event.outcome": "success", "event.id": record["eventID"],
            "event.time": record["eventTime"], "account.id": account,
            "actor.id": identity["arn"], "target.id": target, flag: True}
