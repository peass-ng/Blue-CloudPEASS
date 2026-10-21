"""Lex V2 service-role and code-hook setup signals from management events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
import re
from typing import Any, Iterable

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9]{10}\Z")
_ROUTES = {
    "CreateBot": ("BotServiceRoleSelected", "request.lex_bot_service_role_selected"),
    "UpdateBot": ("BotServiceRoleUpdated", "request.lex_bot_service_role_updated"),
    "CreateIntent": ("IntentFulfillmentHookEnabled", "request.lex_intent_hook_enabled"),
    "CreateBotVersion": ("BotModelVersionDeployed", "request.lex_bot_model_version_deployed"),
    "UpdateBotAlias": ("BotAliasHookAttached", "request.lex_bot_alias_hook_attached"),
}


def _stamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request, response = record.get("requestParameters"), record.get("responseElements")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (route is None or record.get("eventSource") != "lex.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _stamp(record.get("eventTime")) is None):
        return []
    bot = response.get("botId") if name == "CreateBot" else request.get("botId")
    if (not isinstance(bot, str) or not _ID.fullmatch(bot)
            or response.get("botId") != bot):
        return []
    if name in ("CreateBot", "UpdateBot"):
        role = request.get("roleArn")
        if (not isinstance(role, str)
                or not role.startswith(f"arn:aws:iam::{account}:role/")
                or len(role) <= len(f"arn:aws:iam::{account}:role/")
                or response.get("roleArn") != role):
            return []
    elif name == "CreateIntent":
        hook = request.get("fulfillmentCodeHook")
        if (not isinstance(hook, Mapping) or hook.get("enabled") is not True
                or hook.get("active") is not True
                or not isinstance(response.get("intentId"), str)
                or not _ID.fullmatch(response["intentId"])):
            return []
    elif name == "CreateBotVersion":
        locale_specs = request.get("botVersionLocaleSpecification")
        version = response.get("botVersion")
        if (not isinstance(locale_specs, Mapping)
                or not any(isinstance(spec, Mapping)
                           and spec.get("sourceBotVersion") == "DRAFT"
                           for spec in locale_specs.values())
                or not isinstance(version, str) or not version.isdigit()):
            return []
    elif name == "UpdateBotAlias":
        aliases = request.get("botAliasLocaleSettings")
        alias = request.get("botAliasId")
        if (not isinstance(aliases, Mapping)
                or not isinstance(alias, str) or not _ID.fullmatch(alias)
                or response.get("botAliasId") != alias
                or not isinstance(request.get("botVersion"), str)
                or not request["botVersion"].isdigit()):
            return []
        def attached(settings: Any) -> bool:
            if not isinstance(settings, Mapping) or settings.get("enabled") is not True:
                return False
            spec = settings.get("codeHookSpecification")
            hook = spec.get("lambdaCodeHook") if isinstance(spec, Mapping) else None
            arn = hook.get("lambdaARN") if isinstance(hook, Mapping) else None
            return (isinstance(hook, Mapping)
                    and hook.get("codeHookInterfaceVersion") == "1.0"
                    and isinstance(arn, str)
                    and arn.startswith(f"arn:aws:lambda:{region}:{account}:function:")
                    and len(arn) > len(f"arn:aws:lambda:{region}:{account}:function:"))
        if not any(attached(settings) for settings in aliases.values()):
            return []
    actor = record.get("userIdentity")
    synthetic, marker = route
    return [{
        "cloud.provider": "aws", "event.source": "lex.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": bot, marker: True,
    }]


def correlate_role_hook(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    role_events: dict[tuple[str, str], list[tuple[datetime, Mapping[str, Any]]]] = {}
    hook_events: list[tuple[datetime, Mapping[str, Any]]] = []
    for record in records:
        normalized = normalize(record)
        if not normalized:
            continue
        event = normalized[0]
        stamp = _stamp(event["event.time"])
        if stamp is None:
            continue
        key = event["account.id"], event["target.id"]
        if event["event.name"] == "BotServiceRoleUpdated":
            role_events.setdefault(key, []).append((stamp, event))
        elif event["event.name"] == "BotAliasHookAttached":
            hook_events.append((stamp, event))
    output: list[dict[str, Any]] = []
    for hook_time, hook in hook_events:
        key = hook["account.id"], hook["target.id"]
        prior = [(stamp, event) for stamp, event in role_events.get(key, [])
                 if timedelta(0) <= hook_time - stamp <= timedelta(hours=1)]
        if not prior:
            continue
        _, role = max(prior, key=lambda item: item[0])
        output.append({
            "cloud.provider": "aws", "event.source": "lex.amazonaws.com",
            "event.name": "BotRoleAndHookConfigured", "event.outcome": "success",
            "event.id": hook["event.id"], "event.time": hook["event.time"],
            "account.id": hook["account.id"],
            "actor.id": hook["actor.id"], "target.id": hook["target.id"],
            "request.lex_role_hook_configured": True,
        })
    return output
