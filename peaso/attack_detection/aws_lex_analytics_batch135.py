"""Lex V2 management signals for analytics, model export, and utterance deletion."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9]{10}\Z")
_ROUTES = {
    "ListAggregatedUtterances": ("AggregatedUtterancesListed", "request.aggregated_utterances_listed", True),
    "ListUtteranceAnalyticsData": ("UtteranceAnalyticsListed", "request.utterance_analytics_listed", True),
    "ListSessionAnalyticsData": ("SessionAnalyticsListed", "request.session_analytics_listed", True),
    "CreateExport": ("BotModelExportCreated", "request.bot_model_export_created", False),
    "DescribeExport": ("BotModelExportDescribed", "request.bot_model_export_described", True),
    "DeleteExport": ("BotModelExportDeleted", "request.bot_model_export_deleted", False),
    "DeleteUtterances": ("UtterancesDeleted", "request.utterances_deleted", False),
}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (route is None or record.get("eventSource") != "lex.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not _text(record.get("eventID")) or not _text(record.get("eventTime"))
            or not isinstance(request, Mapping)):
        return []
    if isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []

    if name == "CreateExport":
        specification = request.get("resourceSpecification")
        bot = specification.get("botExportSpecification") if isinstance(specification, Mapping) else None
        if (not isinstance(bot, Mapping) or request.get("fileFormat") != "LexJson"
                or not _text(bot.get("botVersion")) or not isinstance(response, Mapping)
                or not isinstance(response.get("exportId"), str)
                or not _ID.fullmatch(response["exportId"])):
            return []
        target = bot.get("botId")
    elif name in ("DescribeExport", "DeleteExport"):
        target = request.get("exportId")
    else:
        target = request.get("botId")
    if not isinstance(target, str) or not _ID.fullmatch(target):
        return []

    if name == "ListAggregatedUtterances":
        duration = request.get("aggregationDuration")
        relative = duration.get("relativeAggregationDuration") if isinstance(duration, Mapping) else None
        if (not isinstance(relative, Mapping) or relative.get("timeDimension") != "Hours"
                or not isinstance(relative.get("timeValue"), int)
                or isinstance(relative["timeValue"], bool)
                or not 1 <= relative["timeValue"] <= 24
                or not _text(request.get("localeId"))):
            return []
    if name in ("ListUtteranceAnalyticsData", "ListSessionAnalyticsData"):
        start, end = request.get("startDateTime"), request.get("endDateTime")
        if (not isinstance(start, (int, float)) or isinstance(start, bool)
                or not isinstance(end, (int, float)) or isinstance(end, bool)
                or start <= 0 or end <= start):
            return []
    if name == "DeleteUtterances":
        if not _text(request.get("localeId")) or not _text(request.get("sessionId")):
            return []

    actor = record.get("userIdentity")
    synthetic, flag, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "lex.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target, flag: True,
    }]
