"""Lex V2 test-set record access from management events."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ID = re.compile(r"[A-Za-z0-9]{10}\Z")


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    request = record.get("requestParameters")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    if (record.get("eventSource") != "lex.amazonaws.com"
            or record.get("eventName") != "ListTestSetRecords"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(request, Mapping)
            or not isinstance(request.get("testSetId"), str)
            or not _ID.fullmatch(request["testSetId"])
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
    actor = record.get("userIdentity")
    return [{
        "cloud.provider": "aws", "event.source": "lex.amazonaws.com",
        "event.name": "TestSetRecordsListed", "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account,
        "actor.id": actor.get("arn") if isinstance(actor, Mapping) else None,
        "target.id": request["testSetId"],
        "request.lex_test_set_records_listed": True,
    }]
