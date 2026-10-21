"""Normalize observed Lex V2 CloudTrail data events without conversation content."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9]{10}\Z")
_ROUTES = {
    "RecognizeText": ("TextRecognized", "request.lex_runtime_text_recognized", False),
    "RecognizeUtterance": ("UtteranceRecognized", "request.lex_runtime_utterance_recognized", False),
    "GetSession": ("SessionRead", "request.lex_runtime_session_read", True),
    "PutSession": ("SessionChanged", "request.lex_runtime_session_changed", False),
    "DeleteSession": ("SessionDeleted", "request.lex_runtime_session_deleted", False),
}


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    name = record.get("eventName")
    route = _ROUTES.get(name) if isinstance(name, str) else None
    request = record.get("requestParameters")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (route is None or record.get("eventSource") != "lex.amazonaws.com"
            or record.get("eventCategory") != "Data"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not False
            or record.get("readOnly") is not route[2]
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(request, Mapping)
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or not isinstance(record.get("eventTime"), str)):
        return []
    try:
        stamp = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return []
    except ValueError:
        return []
    bot, alias, locale, session = (request.get(key) for key in
                                   ("botId", "botAliasId", "localeId", "sessionId"))
    if (not isinstance(bot, str) or not _ID.fullmatch(bot)
            or not isinstance(alias, str) or not _ID.fullmatch(alias)
            or not isinstance(locale, str) or not locale.strip()
            or not isinstance(session, str) or len(session) < 2):
        return []
    target = f"arn:aws:lex:{region}:{account}:bot-alias/{bot}/{alias}"
    resources = record.get("resources")
    if (not isinstance(resources, list)
            or not any(isinstance(item, Mapping)
                       and item.get("type") == "AWS::Lex::BotAlias"
                       and item.get("ARN") == target for item in resources)):
        return []
    if name == "RecognizeUtterance" and request.get("requestContentType") not in (
            "text/plain; charset=utf-8", "text/plain;charset=utf-8"):
        # Audio paths are not yet covered by this text-mode laboratory.
        return []
    actor = record.get("userIdentity")
    synthetic, marker, _ = route
    return [{
        "cloud.provider": "aws", "event.source": "lex.amazonaws.com",
        "event.name": synthetic, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": target, marker: True,
    }]
