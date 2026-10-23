"""Detect three distinct HealthOmics read sets fetched by one actor."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
import hashlib
from typing import Any

from .aws_healthomics_sequence_b415 import normalize as normalize_read_set


WINDOW = timedelta(minutes=15)


def correlate(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One alert per actor and store per window; IDs stay out of findings."""
    candidates = []
    seen_events = set()
    for record in records:
        if record.get("eventName") != "GetReadSet":
            continue
        event = normalize_read_set(record)
        if event is None or event["event.id"] in seen_events:
            continue
        seen_events.add(event["event.id"])
        request = record["requestParameters"]
        when = datetime.fromisoformat(event["event.time"].replace("Z", "+00:00"))
        key = (event["account.id"], record["awsRegion"], event["actor.id"],
               request["sequenceStoreId"])
        candidates.append((when, key, request["id"], event))
    candidates.sort(key=lambda item: (item[0], item[3]["event.id"]))
    windows: dict[tuple[str, ...], deque[tuple[datetime, str]]] = defaultdict(deque)
    counts: dict[tuple[str, ...], dict[str, int]] = defaultdict(dict)
    last_alert: dict[tuple[str, ...], datetime] = {}
    alerts = []
    for when, key, read_set, event in candidates:
        window, counter = windows[key], counts[key]
        while window and when - window[0][0] > WINDOW:
            _, expired = window.popleft()
            counter[expired] -= 1
            if counter[expired] == 0:
                del counter[expired]
        window.append((when, read_set))
        counter[read_set] = counter.get(read_set, 0) + 1
        if len(counter) < 3 or (key in last_alert and when - last_alert[key] <= WINDOW):
            continue
        last_alert[key] = when
        account, region, actor, store = key
        target = "sha256:" + hashlib.sha256(
            f"{account}:{region}:sequence:{store}".encode()).hexdigest()[:24]
        alerts.append({
            "cloud.provider": "aws", "event.source": "omics.amazonaws.com",
            "event.name": "HealthOmicsBulkReadSetRetrieval",
            "event.outcome": "success", "event.time": event["event.time"],
            "event.id": "sha256:" + hashlib.sha256(
                f"{account}:{region}:{actor}:{store}:{event['event.id']}".encode()
            ).hexdigest()[:24],
            "account.id": account, "actor.id": actor, "target.id": target,
            "request.healthomics_bulk_read_sets": True,
            "request.healthomics_distinct_read_set_count": len(counter),
        })
    return alerts
