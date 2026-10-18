"""Bounded, read-only CloudTrail Event History retrieval for selector correlation.

``complete`` means the requested regional LookupEvents pages were exhausted and
all returned entries were parseable within configured limits. It cannot prove
that recent events have already arrived in Event History. Event History only
covers management events in this Region for the past 90 days; it is independent
of trail delivery, and it does not supply older events or data events.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


_ACCOUNT = re.compile(r"\d{12}")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-\d+")


@dataclass(frozen=True)
class SelectorHistoryResult:
    events: tuple[dict[str, Any], ...]
    complete: bool
    partial_reason: str | None
    pages_read: int
    records_seen: int
    coverage: str = ("Regional CloudTrail Event History management events within the requested interval "
                     "(at most 90 days); recent events may not yet have arrived.")


def _event_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def read_aws_selector_event_history(
    client: Any, *, account_id: str, region: str,
    start_time: datetime, end_time: datetime,
    max_pages: int = 40, max_records: int = 2000,
) -> SelectorHistoryResult:
    """Read PutEventSelectors records using fixed LookupEvents parameters.

    The caller supplies an already authorized CloudTrail client for ``region``.
    Errors, token cycles, caps, and malformed entries return partial results;
    callers must pass ``complete=False`` to any transition correlator then.
    """
    if (not _ACCOUNT.fullmatch(account_id) or not _REGION.fullmatch(region)
            or not isinstance(start_time, datetime) or not isinstance(end_time, datetime)
            or start_time.tzinfo is None or end_time.tzinfo is None
            or start_time >= end_time
            or not isinstance(max_pages, int) or isinstance(max_pages, bool) or not 1 <= max_pages <= 100
            or not isinstance(max_records, int) or isinstance(max_records, bool) or not 1 <= max_records <= 5000):
        raise ValueError("invalid_selector_history_bounds")

    base = {"StartTime": start_time, "EndTime": end_time,
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutEventSelectors"}]}
    events: dict[str, dict[str, Any]] = {}
    token: str | None = None
    used_tokens: set[str] = set()
    pages_read = 0
    records_seen = 0
    partial_reason: str | None = None
    for _ in range(max_pages):
        params = {**base, "MaxResults": min(50, max_records - records_seen)}
        if token is not None:
            params["NextToken"] = token
            used_tokens.add(token)
        try:
            page = client.lookup_events(**params)
        except Exception:
            partial_reason = "lookup_failed"
            break
        pages_read += 1
        rows = page.get("Events") if isinstance(page, Mapping) else None
        if not isinstance(rows, list):
            partial_reason = "malformed_page"
            break
        if len(rows) > params["MaxResults"]:
            partial_reason = "malformed_page"
            break
        for row in rows:
            if records_seen >= max_records:
                partial_reason = "record_cap"
                break
            records_seen += 1
            if not isinstance(row, Mapping) or not isinstance(row.get("CloudTrailEvent"), str):
                partial_reason = "malformed_event"
                continue
            try:
                event = json.loads(row["CloudTrailEvent"])
            except (TypeError, ValueError):
                partial_reason = "malformed_event"
                continue
            if not isinstance(event, dict):
                partial_reason = "malformed_event"
                continue
            event_id = event.get("eventID")
            event_time = _event_time(event.get("eventTime"))
            if (not isinstance(event_id, str) or not event_id or event_time is None
                    or not isinstance(event.get("recipientAccountId"), str)
                    or not isinstance(event.get("awsRegion"), str)
                    or event.get("eventName") != "PutEventSelectors"
                    or event.get("eventSource") != "cloudtrail.amazonaws.com"
                    or row.get("EventId", event_id) != event_id):
                partial_reason = "malformed_event"
                continue
            if not start_time <= event_time <= end_time:
                partial_reason = "event_outside_window"
                continue
            if event["recipientAccountId"] != account_id or event["awsRegion"] != region:
                continue
            previous = events.get(event_id)
            if previous is not None and previous != event:
                partial_reason = "conflicting_duplicate"
                continue
            events[event_id] = event
        if records_seen >= max_records:
            partial_reason = "record_cap"
            break
        next_token = page.get("NextToken")
        if next_token is not None and (not isinstance(next_token, str) or not next_token):
            partial_reason = "malformed_token"
            break
        if next_token in used_tokens:
            partial_reason = "token_cycle"
            break
        if next_token is None:
            break
        token = next_token
    else:
        partial_reason = "page_cap"

    ordered = tuple(sorted(events.values(), key=lambda item: (_event_time(item["eventTime"]), item["eventID"])))
    return SelectorHistoryResult(ordered, partial_reason is None, partial_reason, pages_read, records_seen)
