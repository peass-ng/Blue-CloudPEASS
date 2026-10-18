"""Correlate complete CloudTrail selector writes within a declared complete window.

This describes two observed API results, not malicious intent, current trail
state, or whether another trail still logs management writes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from .aws_security_controls import _arn, _event_time, _trail_reference, normalize_aws_security_control


def _complete_selector_write(record: Mapping[str, Any]) -> tuple[str, str, datetime] | None:
    """Return (exact trail ARN, selector mode, event time) for one complete result."""
    request = record.get("requestParameters")
    response = record.get("responseElements")
    identity = record.get("userIdentity")
    account = record.get("recipientAccountId")
    region = record.get("awsRegion")
    if (record.get("eventSource") != "cloudtrail.amazonaws.com"
            or record.get("eventName") != "PutEventSelectors"
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") not in (None, True)
            or record.get("readOnly") not in (None, False)
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")
            or not isinstance(identity, Mapping)
            or not isinstance(account, str) or not isinstance(region, str)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _event_time(record.get("eventTime")) is None):
        return None
    actor_arn = _arn(identity.get("arn"))
    if (actor_arn is None or actor_arn[4] != account or identity.get("accountId") != account
            or not isinstance(identity.get("type"), str) or not identity["type"]):
        return None
    trail_name = _trail_reference(request.get("trailName"), account, region, actor_arn[1])
    trail_arn = response.get("trailARN")
    if (trail_name is None or not isinstance(trail_arn, str) or not trail_arn.startswith("arn:")
            or _trail_reference(trail_arn, account, region, actor_arn[1]) != trail_name
            or request.get("advancedEventSelectors") or response.get("advancedEventSelectors")):
        return None
    request_selectors = request.get("eventSelectors")
    response_selectors = response.get("eventSelectors")
    if (not isinstance(request_selectors, list) or len(request_selectors) != 1
            or not isinstance(response_selectors, list) or len(response_selectors) != 1
            or not isinstance(request_selectors[0], Mapping)
            or not isinstance(response_selectors[0], Mapping)):
        return None
    request_selector = request_selectors[0]
    response_selector = response_selectors[0]
    mode = request_selector.get("readWriteType")
    if (mode not in {"All", "ReadOnly", "WriteOnly"}
            or response_selector.get("readWriteType") != mode
            or request_selector.get("includeManagementEvents") is not True
            or response_selector.get("includeManagementEvents") is not True):
        return None
    return trail_arn, mode, datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))


def correlate_aws_selector_changes(
    records: Iterable[Mapping[str, Any]], *, complete_window: bool = False,
    max_gap_seconds: int = 3600,
) -> list[dict[str, Any]]:
    """Report observed All→ReadOnly management-selector transitions per trail.

    ``complete_window`` is the caller's assertion that every selector write in
    the ordered interval was ingested. A missing page or unknown coverage must
    pass False and yields no correlation. The input must be ordered by eventTime.
    Any unparseable or ambiguous selector write clears prior baselines.
    """
    if complete_window is not True or not isinstance(max_gap_seconds, int) or isinstance(max_gap_seconds, bool) or not 0 < max_gap_seconds <= 86400:
        return []
    baselines: dict[str, Mapping[str, Any]] = {}
    matches: list[dict[str, Any]] = []
    previous_time: datetime | None = None
    for record in records:
        if (record.get("eventSource"), record.get("eventName")) != ("cloudtrail.amazonaws.com", "PutEventSelectors"):
            continue
        timestamp = _event_time(record.get("eventTime"))
        if timestamp is None:
            baselines.clear()
            continue
        observed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if previous_time is not None and observed_time <= previous_time:
            # Equal timestamps cannot establish sequence; out-of-order input
            # cannot prove that no intervening write was hidden.
            return []
        previous_time = observed_time
        if record.get("errorCode"):
            # An explicitly failed API call did not replace the selector set.
            continue
        write = _complete_selector_write(record)
        if write is None:
            baselines.clear()
            continue
        trail_arn, mode, current_time = write
        previous = baselines.pop(trail_arn, None)
        if mode == "ReadOnly" and previous is not None:
            prior_time = datetime.fromisoformat(previous["eventTime"].replace("Z", "+00:00"))
            if 0 < (current_time - prior_time).total_seconds() <= max_gap_seconds:
                current = normalize_aws_security_control(record)
                if current is not None:
                    current.update({
                        "request.management_write_selector_reduced": True,
                        "correlation.previous_event_id": previous["eventID"],
                        "correlation.previous_event_time": previous["eventTime"],
                        "correlation.previous_read_write_type": "All",
                        "correlation.current_read_write_type": "ReadOnly",
                    })
                    matches.append(current)
        if mode == "All":
            baselines[trail_arn] = record
    return matches
