"""Correlate EMR security configuration listing and targeted description."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_WINDOW = timedelta(minutes=15)
_ACTIONS = frozenset({"ListSecurityConfigurations", "DescribeSecurityConfiguration"})


def _accepted(record: Mapping[str, Any]) -> tuple[str, str, str, datetime, str | None] | None:
    action = record.get("eventName")
    if (record.get("eventSource") != "elasticmapreduce.amazonaws.com"
            or action not in _ACTIONS
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
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    name = None
    if action == "DescribeSecurityConfiguration":
        if (not isinstance(request, Mapping)
                or not isinstance(request.get("name"), str)
                or not _NAME.fullmatch(request["name"])):
            return None
        name = request["name"]
    stamp = record.get("eventTime")
    if not isinstance(stamp, str):
        return None
    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            return None
    except ValueError:
        return None
    return account, region, identity["arn"], moment, name


def correlate_aws_emr_security_reads(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Signal listing followed by a named configuration read within 15 minutes."""
    grouped: dict[tuple[str, str, str], list[tuple[datetime, Mapping[str, Any], str | None]]] = {}
    for record in records:
        accepted = _accepted(record)
        if accepted is None:
            continue
        account, region, actor, moment, name = accepted
        key = account, region, actor
        if len(grouped.setdefault(key, [])) < 10_000:
            grouped[key].append((moment, record, name))
    results = []
    for (account, region, actor), items in grouped.items():
        items.sort(key=lambda item: item[0])
        last_list: datetime | None = None
        emitted: set[str] = set()
        for moment, record, name in items:
            if record["eventName"] == "ListSecurityConfigurations":
                last_list = moment
                continue
            if last_list is None or moment - last_list > _WINDOW or name is None or name in emitted:
                continue
            emitted.add(name)
            target = hashlib.sha256(
                f"emr-security-config:{account}:{region}:{name}".encode("utf-8")
            ).hexdigest()[:24]
            results.append({
                "cloud.provider": "aws", "event.source": "elasticmapreduce.amazonaws.com",
                "event.name": "EmrSecurityConfigurationReadAfterList", "event.outcome": "success",
                "event.id": record["eventID"], "event.time": record["eventTime"],
                "account.id": account, "actor.id": actor, "target.id": "sha256:" + target,
                "request.emr_security_configuration_read_after_list": True,
                "correlation_evidence": {"window_minutes": 15},
            })
    return results
