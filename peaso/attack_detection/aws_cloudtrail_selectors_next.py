"""CloudTrail management exclusions and Insights selector removal."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _management_excluded(value: Any) -> bool:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        return False
    selector = value[0]
    excluded = selector.get("excludeManagementEventSources")
    return (selector.get("includeManagementEvents") is True
            and isinstance(excluded, list) and bool(excluded)
            and all(x in {"kms.amazonaws.com", "rdsdata.amazonaws.com"} for x in excluded))


def normalize_aws_cloudtrail_selectors(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "cloudtrail.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"PutEventSelectors", "PutInsightSelectors"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    trail = request.get("trailName")
    if not isinstance(trail, str) or not trail:
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "cloudtrail.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId") or identity.get("accountId"),
        "actor.id": identity.get("arn"), "target.id": trail,
        "request.trail_management_sources_excluded": (
            not failed and name == "PutEventSelectors"
            and _management_excluded(request.get("eventSelectors"))
        ),
        "request.trail_insight_selectors_emptied": (
            not failed and name == "PutInsightSelectors"
            and request.get("insightSelectors") == []
        ),
    }
