"""Correlate accepted EMR cluster metadata reads for one cluster."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACTIONS = frozenset({"DescribeCluster", "ListInstances", "ListBootstrapActions"})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_CLUSTER = re.compile(r"j-[A-Z0-9]{8,32}\Z")
_WINDOW = timedelta(minutes=15)


def _accepted(record: Mapping[str, Any]) -> tuple[str, str, str, str, datetime] | None:
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or record.get("eventName") not in _ACTIONS
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not True
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity, request = record.get("userIdentity"), record.get("requestParameters")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(identity.get("arn"), str)
            or not isinstance(request, Mapping)
            or not isinstance(request.get("clusterId"), str)
            or not _CLUSTER.fullmatch(request["clusterId"])
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
    return account, region, identity["arn"], request["clusterId"], moment


def correlate_aws_emr_inventory(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Signal three distinct reads of one cluster within fifteen minutes."""
    grouped: dict[tuple[str, str, str, str], list[tuple[datetime, Mapping[str, Any]]]] = {}
    for record in records:
        valid = _accepted(record)
        if valid is None:
            continue
        account, region, actor, cluster, moment = valid
        key = account, region, actor, cluster
        if len(grouped.setdefault(key, [])) < 10_000:
            grouped[key].append((moment, record))
    results = []
    for (account, region, actor, cluster), items in grouped.items():
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
                f"emr-inventory:{account}:{region}:{cluster}".encode("utf-8")
            ).hexdigest()[:24]
            results.append({
                "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
                "event.name": "EmrClusterInventorySweep", "event.outcome": "success",
                "event.id": last["eventID"], "event.time": last["eventTime"],
                "account.id": account, "actor.id": actor, "target.id": "sha256:" + target,
                "request.emr_cluster_inventory_sweep": True,
                "correlation_evidence": {"distinct_inventory_actions": len(_ACTIONS),
                                         "window_minutes": 15},
            })
            break
    return results
