"""EventBridge Pipes role/target configuration and template-read correlation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import hashlib
from typing import Any


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _base(record: Mapping[str, Any], names: set[str]) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if record.get("eventSource") != "pipes.amazonaws.com" or record.get("eventName") not in names:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (record.get("eventName") == "DescribePipe")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    request = record.get("requestParameters")
    response = record.get("responseElements")
    if not isinstance(request, Mapping):
        return None
    response = response if isinstance(response, Mapping) else {}
    if response.get("errorCode") or response.get("errorMessage"):
        return None
    return request, response


def _role_target(request: Mapping[str, Any]) -> bool:
    role, target = request.get("RoleArn"), request.get("Target")
    return (isinstance(role, str) and role.startswith("arn:aws:iam::") and ":role/" in role
            and isinstance(target, str) and target.startswith("arn:aws:"))


def normalize_aws_pipes_role_b440(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed = _base(record, {"CreatePipe", "UpdatePipe"})
    if parsed is None:
        return None
    request, response = parsed
    name = request.get("Name")
    if not isinstance(name, str) or not name:
        return None
    actor = record.get("userIdentity")
    actor = actor if isinstance(actor, Mapping) else {}
    accepted = bool(response.get("Name") == name and isinstance(response.get("Arn"), str)
                    and response["Arn"].endswith("/" + name))
    source = request.get("Source")
    return {
        "cloud.provider": "aws", "event.source": "pipes.amazonaws.com",
        "event.name": record["eventName"], "event.outcome": "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"),
        "actor.id": _hash(actor["arn"]) if isinstance(actor.get("arn"), str) else None,
        "target.id": _hash(response["Arn"]) if accepted else None,
        "request.pipes_role_source_target_bound": bool(record["eventName"] == "CreatePipe"
                                                        and accepted and _role_target(request)
                                                        and isinstance(source, str)
                                                        and source.startswith("arn:aws:")),
        "request.pipes_role_target_updated": bool(record["eventName"] == "UpdatePipe"
                                                  and accepted and _role_target(request)),
    }


def correlate_aws_pipes_template_read_b440(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    configured: dict[tuple[str, str], list[tuple[datetime, str]]] = {}
    reads: list[tuple[datetime, str, str, str, Mapping[str, Any]]] = []
    for record in records:
        parsed = _base(record, {"CreatePipe", "UpdatePipe", "DescribePipe"})
        if parsed is None:
            continue
        request, response = parsed
        name = request.get("Name")
        account = record.get("recipientAccountId")
        identity = record.get("userIdentity")
        when = _when(record.get("eventTime"))
        if (not isinstance(name, str) or not name or not isinstance(account, str)
                or len(account) != 12 or not account.isdigit()
                or not isinstance(identity, Mapping) or not isinstance(identity.get("arn"), str)
                or when is None):
            continue
        actor = identity["arn"]
        if record["eventName"] in {"CreatePipe", "UpdatePipe"}:
            params = request.get("TargetParameters")
            template = params.get("InputTemplate") if isinstance(params, Mapping) else None
            if (isinstance(template, str) and bool(template)
                    and response.get("Name") == name):
                configured.setdefault((account, name), []).append((when, actor))
        else:
            reads.append((when, account, name, actor, record))
    result = []
    for when, account, name, actor, record in reads:
        if not any(creator != actor and created <= when <= created + timedelta(hours=2)
                   for created, creator in configured.get((account, name), [])):
            continue
        result.append({
            "cloud.provider": "aws", "event.source": "pipes.amazonaws.com",
            "event.name": "DescribePipe", "event.outcome": "success",
            "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
            "account.id": account, "actor.id": _hash(actor), "target.id": _hash(name),
            "request.pipes_other_actor_read_configured_template": True,
        })
    return result
