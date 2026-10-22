"""Correlate accepted Amazon MQ configuration and user changes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")


def _event(record: Mapping[str, Any]) -> tuple[Any, ...] | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "amazonmq.amazonaws.com"
            or name not in {"UpdateConfiguration", "UpdateBroker", "CreateUser", "UpdateUser"}
            or record.get("eventType") != "AwsApiCall"
            or record.get("eventCategory") != "Management"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    identity = record.get("userIdentity")
    actor = identity.get("arn") if isinstance(identity, Mapping) else None
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not region
            or not isinstance(identity, Mapping) or identity.get("accountId") != account
            or not isinstance(actor, str) or not actor
            or not isinstance(request, Mapping)):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    response = record.get("responseElements")
    value: tuple[str, ...] | None = None
    if name == "UpdateConfiguration":
        revision = response.get("latestRevision") if isinstance(response, Mapping) else None
        config_id = request.get("configuration-id")
        if (not isinstance(config_id, str) or not config_id
                or not isinstance(revision, Mapping)
                or response.get("id") != config_id
                or isinstance(revision.get("revision"), bool)
                or not isinstance(revision.get("revision"), int)):
            return None
        value = (config_id, str(revision["revision"]))
    elif name == "UpdateBroker":
        config, confirmed = request.get("configuration"), response.get("configuration") if isinstance(response, Mapping) else None
        broker_id = request.get("broker-id")
        if (not isinstance(config, Mapping) or not isinstance(confirmed, Mapping)
                or not isinstance(broker_id, str) or not broker_id
                or response.get("brokerId") != broker_id
                or not isinstance(config.get("id"), str) or not config["id"]
                or isinstance(config.get("revision"), bool)
                or not isinstance(config.get("revision"), int)
                or confirmed.get("id") != config["id"]
                or confirmed.get("revision") != config["revision"]):
            return None
        value = (broker_id, config["id"], str(config["revision"]))
    else:
        broker_id, username, groups = request.get("broker-id"), request.get("username"), request.get("groups")
        if (not isinstance(broker_id, str) or not broker_id
                or not isinstance(username, str) or not username
                or not isinstance(groups, list) or not groups
                or not all(isinstance(group, str) and group for group in groups)):
            return None
        value = (broker_id,)
    return when, name, account, region, actor, value, record


def correlate_aws_mq_broker_chain(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """A published revision, matching broker association, and user change within one hour."""
    parsed = [item for record in records if (item := _event(record)) is not None]
    # CloudTrail eventTime has one-second precision. Within that second the
    # exact call order is unavailable, so treat same-second stages as adjacent.
    stage = {"UpdateConfiguration": 0, "UpdateBroker": 1, "CreateUser": 2, "UpdateUser": 2}
    parsed.sort(key=lambda row: (row[0], stage[row[1]]))
    revisions: dict[tuple[str, str, str, str, str], datetime] = {}
    attached: dict[tuple[str, str, str, str], datetime] = {}
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    window = timedelta(hours=1)
    for when, name, account, region, actor, value, record in parsed:
        if name == "UpdateConfiguration":
            config_id, revision = value
            revisions[account, region, actor, config_id, revision] = when
        elif name == "UpdateBroker":
            broker_id, config_id, revision = value
            created = revisions.get((account, region, actor, config_id, revision))
            if created is not None and created <= when and when - created <= window:
                attached[account, region, actor, broker_id] = when
        else:
            broker_id = value[0]
            connected = attached.get((account, region, actor, broker_id))
            event_id = record.get("eventID")
            if (connected is None or not connected <= when or when - connected > window
                    or not isinstance(event_id, str) or not event_id or event_id in seen):
                continue
            seen.add(event_id)
            result.append({
                "cloud.provider": "aws", "event.source": "amazonmq.amazonaws.com",
                "event.name": name, "event.outcome": "success",
                "event.id": event_id, "event.time": record["eventTime"],
                "account.id": account, "actor.id": actor,
                "target.id": "sha256:" + hashlib.sha256(broker_id.encode()).hexdigest()[:24],
                "request.mq_configuration_user_chain": True,
            })
    return result
