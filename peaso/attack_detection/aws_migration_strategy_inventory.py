"""Correlate a bounded Migration Hub Strategy Recommendations inventory sweep."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACTIONS = frozenset({
    "ListCollectors", "ListServers", "ListApplicationComponents",
    "ListImportFileTask", "GetPortfolioPreferences",
})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_WINDOW = timedelta(minutes=15)
_READ_ONLY = {
    "ListCollectors": True,
    "ListServers": False,
    "ListApplicationComponents": False,
    "ListImportFileTask": True,
    "GetPortfolioPreferences": True,
}


def _accepted(record: Mapping[str, Any]) -> tuple[str, str, str, datetime] | None:
    if (record.get("eventSource") != "migrationhub-strategy.amazonaws.com"
            or record.get("eventName") not in _ACTIONS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not _READ_ONLY[record["eventName"]]
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    stamp = record.get("eventTime")
    if not isinstance(stamp, str):
        return None
    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            return None
    except ValueError:
        return None
    return account, region, identity["arn"], moment


def correlate_aws_migration_strategy_inventory(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Alert once per actor/Region when all five inventory APIs succeed."""
    grouped: dict[tuple[str, str, str], list[tuple[datetime, Mapping[str, Any]]]] = {}
    for record in records:
        valid = _accepted(record)
        if valid is None:
            continue
        account, region, actor, moment = valid
        key = account, region, actor
        if len(grouped.setdefault(key, [])) < 10_000:
            grouped[key].append((moment, record))
    results = []
    for (account, region, actor), items in grouped.items():
        items.sort(key=lambda item: item[0])
        window: deque[tuple[datetime, Mapping[str, Any]]] = deque()
        counts: Counter[str] = Counter()
        for moment, last in items:
            window.append((moment, last))
            counts[last["eventName"]] += 1
            while window and moment - window[0][0] > _WINDOW:
                _, expired = window.popleft()
                counts[expired["eventName"]] -= 1
                if counts[expired["eventName"]] == 0:
                    del counts[expired["eventName"]]
            if counts.keys() != _ACTIONS:
                continue
            target = hashlib.sha256(
                f"migration-strategy-inventory:{account}:{region}:{actor}".encode("utf-8")
            ).hexdigest()[:24]
            results.append({
                "cloud.provider": "aws", "event.source": "migrationhub-strategy.amazonaws.com",
                "event.name": "MigrationStrategyInventorySweep", "event.outcome": "success",
                "event.id": last["eventID"], "event.time": last["eventTime"],
                "account.id": account, "actor.id": actor, "target.id": "sha256:" + target,
                "request.migration_strategy_inventory_sweep": True,
                "correlation_evidence": {"distinct_inventory_actions": len(_ACTIONS),
                                         "window_minutes": 15},
            })
            break
    return results
