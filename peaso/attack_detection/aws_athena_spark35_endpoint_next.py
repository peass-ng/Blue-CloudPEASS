"""Correlate a Spark 3.5 bearer-token request with another actor's session.

CloudTrail may carry the endpoint and AuthToken in responseElements. This
projection deliberately excludes the entire response, session ID, and role ARN.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{7,127}\Z")
_NAMES = {"CreateWorkGroup", "StartSession", "GetSessionEndpoint"}


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _identity(value: Any, account: str) -> tuple[str, str] | None:
    if not isinstance(value, Mapping) or value.get("accountId") != account:
        return None
    actor = value.get("arn")
    if not isinstance(actor, str) or not actor.startswith("arn:"):
        return None
    if value.get("type") == "AssumedRole":
        context = value.get("sessionContext")
        issuer = context.get("sessionIssuer") if isinstance(context, Mapping) else None
        principal = issuer.get("arn") if isinstance(issuer, Mapping) else None
        if not isinstance(principal, str) or not principal.startswith("arn:"):
            return None
    else:
        principal = actor
    return actor, principal


def _valid(record: Mapping[str, Any]) -> tuple | None:
    name = record.get("eventName")
    if (record.get("eventSource") != "athena.amazonaws.com" or name not in _NAMES
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not (name == "GetSessionEndpoint")
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request = record.get("requestParameters")
    when, event_id = _when(record.get("eventTime")), record.get("eventID")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(event_id, str)
            or not event_id or when is None):
        return None
    identity = _identity(record.get("userIdentity"), account)
    if identity is None:
        return None
    response = record.get("responseElements")
    return account, region, *identity, when, request, response if isinstance(response, Mapping) else {}


def _workgroup_arn(account: str, region: str, name: str) -> str:
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return f"arn:{partition}:athena:{region}:{account}:workgroup/{name}"


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    workgroups = []
    sessions = []
    endpoint_reads = []
    for record in records:
        values = _valid(record)
        if values is None:
            continue
        account, region, actor, principal, when, request, response = values
        name = record["eventName"]
        if name == "CreateWorkGroup":
            config = request.get("configuration")
            wg = request.get("name")
            if not isinstance(config, Mapping) or not isinstance(wg, str) or not _NAME.fullmatch(wg):
                continue
            engine = config.get("engineVersion")
            role = config.get("executionRole")
            if (not isinstance(engine, Mapping)
                    or engine.get("selectedEngineVersion") != "Apache Spark version 3.5"
                    or not isinstance(role, str)
                    or not re.fullmatch(rf"arn:aws(?:-us-gov|-cn)?:iam::{account}:role/[A-Za-z0-9+=,.@_/-]+", role)):
                continue
            workgroups.append((when, account, region, wg, record["eventID"]))
        elif name == "StartSession":
            wg, session_id = request.get("workGroup"), response.get("sessionId")
            if (isinstance(wg, str) and _NAME.fullmatch(wg)
                    and isinstance(session_id, str) and _SESSION.fullmatch(session_id)):
                sessions.append((when, account, region, principal, wg, session_id, record["eventID"]))
        else:
            session_id = request.get("sessionId")
            if isinstance(session_id, str) and _SESSION.fullmatch(session_id):
                endpoint_reads.append((when, account, region, actor, principal, session_id, record))
    out = []
    for when, account, region, actor, principal, session_id, record in endpoint_reads:
        matches = [entry for entry in sessions if entry[1:3] == (account, region)
                   and entry[3] != principal and entry[5] == session_id
                   and timedelta(0) <= when-entry[0] <= timedelta(hours=24)]
        for start in sorted(matches, reverse=True):
            wg = start[4]
            created = [entry for entry in workgroups if entry[1:4] == (account, region, wg)
                       and timedelta(0) <= start[0]-entry[0] <= timedelta(hours=24)]
            if not created:
                continue
            out.append({"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
                        "event.name": "AthenaSpark35CrossActorGetSessionEndpoint",
                        "event.outcome": "success", "event.id": record["eventID"],
                        "event.time": record["eventTime"], "account.id": account,
                        "actor.id": actor, "target.id": _workgroup_arn(account, region, wg),
                        "request.athena_spark35_cross_actor_endpoint_requested": True,
                        "correlation_evidence": {"source_event_id": start[6],
                                                 "workgroup_event_id": max(created)[4]}})
            break
    return out
