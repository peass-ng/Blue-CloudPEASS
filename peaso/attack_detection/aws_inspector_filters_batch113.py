"""Amazon Inspector filter control-plane signals with bounded criteria correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{3,128}\Z")
_FILTER_ID = re.compile(r"[A-Za-z0-9-]{1,128}\Z")
_WINDOW = timedelta(hours=1)
_NAMES = {"CreateFilter", "UpdateFilter", "TagResource", "UntagResource", "DeleteFilter"}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _base(record: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any]] | None:
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if (record.get("eventSource") != "inspector2.amazonaws.com"
            or record.get("eventName") not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or (isinstance(response, Mapping)
                and (response.get("errorCode") or response.get("errorMessage")))
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _time(record.get("eventTime")) is None
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping)):
        return None
    return account, region, request


def _filter_arn(value: Any, account: str, region: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:inspector2:{region}:{account}:owner/"
    if not value.startswith(prefix):
        return None
    parts = value[len(prefix):].split("/")
    if len(parts) != 3 or parts[1] != "filter":
        return None
    owner, _, filter_id = parts
    if (owner != account and re.fullmatch(r"o-[a-z0-9]{10,32}", owner) is None):
        return None
    return value if _FILTER_ID.fullmatch(filter_id) else None


def _criteria(value: Any) -> str | None:
    if not isinstance(value, Mapping) or not value:
        return None
    if any(not isinstance(key, str) or not isinstance(rows, list) or not rows
           or any(not isinstance(row, Mapping) for row in rows)
           for key, rows in value.items()):
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _finding(record: Mapping[str, Any], account: str, arn: str,
             name: str, flag: str, prior: str | None = None) -> dict[str, Any]:
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": "inspector2.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": arn, flag: True,
    }
    if prior:
        result["correlation_evidence"] = {"prior_event_id": prior}
    return result


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    base = _base(record)
    if base is None:
        return []
    account, region, request = base
    response = record.get("responseElements")
    name = record["eventName"]
    if name == "CreateFilter":
        if (request.get("action") != "SUPPRESS"
                or not isinstance(request.get("name"), str)
                or not _NAME.fullmatch(request["name"])
                or _criteria(request.get("filterCriteria")) is None
                or not isinstance(response, Mapping)):
            return []
        arn = _filter_arn(response.get("arn"), account, region)
        return [_finding(record, account, arn, "InspectorSuppressionFilterCreated",
                         "request.inspector_suppression_filter_created")] if arn else []
    if name == "UpdateFilter":
        arn = _filter_arn(request.get("filterArn"), account, region)
        if (not arn or request.get("action") != "SUPPRESS"
                or not isinstance(response, Mapping) or response.get("arn") != arn):
            return []
        return [_finding(record, account, arn, "InspectorSuppressionFilterUpdated",
                         "request.inspector_suppression_filter_updated")]
    if name in {"TagResource", "UntagResource"}:
        arn = _filter_arn(request.get("resourceArn"), account, region)
        changed = request.get("tags") if name == "TagResource" else request.get("tagKeys")
        untag_keys_valid = (isinstance(changed, str) and bool(changed)
                            or isinstance(changed, list) and bool(changed)
                            and all(isinstance(tag, str) and bool(tag) for tag in changed))
        if (not arn or not changed
                or (name == "TagResource" and not isinstance(changed, Mapping))
                or (name == "UntagResource" and not untag_keys_valid)):
            return []
        synthetic = "InspectorFilterTagged" if name == "TagResource" else "InspectorFilterUntagged"
        flag = "request.inspector_filter_tagged" if name == "TagResource" else "request.inspector_filter_untagged"
        return [_finding(record, account, arn, synthetic, flag)]
    arn = _filter_arn(request.get("arn"), account, region)
    if not arn or not isinstance(response, Mapping) or response.get("arn") != arn:
        return []
    return [_finding(record, account, arn, "InspectorFilterDeleted",
                     "request.inspector_filter_deleted")]


def correlate_criteria_change(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Report a SUPPRESS filter's observed criteria change within one hour."""
    rows: list[tuple[datetime, Mapping[str, Any], str, str, str, str]] = []
    seen: set[str] = set()
    for record in records:
        if record.get("eventName") not in {"CreateFilter", "UpdateFilter", "DeleteFilter"}:
            continue
        base = _base(record)
        if base is None or record["eventID"] in seen:
            continue
        account, region, request = base
        response = record.get("responseElements")
        arn = (response.get("arn") if isinstance(response, Mapping)
               else None) if record["eventName"] == "CreateFilter" else (
                   request.get("filterArn") if record["eventName"] == "UpdateFilter"
                   else request.get("arn"))
        arn = _filter_arn(arn, account, region)
        when = _time(record.get("eventTime"))
        if (not arn or when is None or not isinstance(response, Mapping)
                or response.get("arn") != arn):
            continue
        criteria = _criteria(request.get("filterCriteria"))
        if record["eventName"] != "DeleteFilter" and criteria is None:
            continue
        seen.add(record["eventID"])
        rows.append((when, record, account, region, arn, criteria or ""))
    priority = {"CreateFilter": 0, "UpdateFilter": 1, "DeleteFilter": 2}
    rows.sort(key=lambda row: (row[0], priority[row[1]["eventName"]], row[1]["eventID"]))
    prior: dict[str, tuple[datetime, str, str]] = {}
    results = []
    for when, record, account, region, arn, criteria in rows:
        name = record["eventName"]
        if name == "DeleteFilter":
            prior.pop(arn, None)
            continue
        previous = prior.get(arn)
        if (name == "UpdateFilter" and record["requestParameters"].get("action") == "SUPPRESS"
                and previous and timedelta(0) <= when - previous[0] <= _WINDOW
                and previous[1] != criteria):
            results.append(_finding(record, account, arn,
                "InspectorSuppressionCriteriaChanged",
                "request.inspector_suppression_criteria_changed", previous[2]))
        prior[arn] = when, criteria, record["eventID"]
    return results
