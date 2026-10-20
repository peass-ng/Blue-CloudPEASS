"""Correlate Athena query-history reads with a different query starter.

CloudTrail omits read responses. The output records accepted API reads, not
the SQL, rows, query ID, S3 path, or proof the caller used those values.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_READS = {"ListQueryExecutions", "GetQueryExecution", "BatchGetQueryExecution",
          "GetQueryResults", "GetQueryRuntimeStatistics"}
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_WORKGROUP = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


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


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    starts = []
    reads = []
    for record in records:
        name = record.get("eventName")
        if (record.get("eventSource") != "athena.amazonaws.com"
                or name not in _READS | {"StartQueryExecution"}
                or record.get("eventCategory") != "Management"
                or record.get("eventType") != "AwsApiCall"
                or record.get("managementEvent") is not True
                or record.get("readOnly") is not (name in _READS)
                or record.get("errorCode") or record.get("errorMessage")):
            continue
        account, region = record.get("recipientAccountId"), record.get("awsRegion")
        request, when = record.get("requestParameters"), _when(record.get("eventTime"))
        if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
                or not isinstance(region, str) or not _REGION.fullmatch(region)
                or not isinstance(request, Mapping) or when is None
                or not isinstance(record.get("eventID"), str) or not record["eventID"]):
            continue
        identity = _identity(record.get("userIdentity"), account)
        if identity is None:
            continue
        actor, principal = identity
        if name == "StartQueryExecution":
            workgroup = request.get("workGroup")
            response = record.get("responseElements")
            qid = response.get("queryExecutionId") if isinstance(response, Mapping) else None
            if (isinstance(workgroup, str) and _WORKGROUP.fullmatch(workgroup)
                    and isinstance(qid, str) and _UUID.fullmatch(qid)):
                starts.append((when, account, region, principal, workgroup, qid, record))
            continue
        if name == "ListQueryExecutions":
            workgroup = request.get("workGroup")
            if not isinstance(workgroup, str) or not _WORKGROUP.fullmatch(workgroup):
                continue
            qids = ()
        elif name == "BatchGetQueryExecution":
            values = request.get("queryExecutionIds")
            if not isinstance(values, list) or not 1 <= len(values) <= 50:
                continue
            qids = tuple(x for x in values if isinstance(x, str) and _UUID.fullmatch(x))
            if len(qids) != len(values):
                continue
            workgroup = None
        else:
            qid = request.get("queryExecutionId")
            if not isinstance(qid, str) or not _UUID.fullmatch(qid):
                continue
            qids = (qid,)
            workgroup = None
        reads.append((when, account, region, actor, principal, name, workgroup, qids, record))

    out = []
    flag_by_name = {
        "ListQueryExecutions": "request.athena_cross_actor_query_listed",
        "GetQueryExecution": "request.athena_cross_actor_query_execution_read",
        "BatchGetQueryExecution": "request.athena_cross_actor_batch_query_execution_read",
        "GetQueryResults": "request.athena_cross_actor_query_results_read",
        "GetQueryRuntimeStatistics": "request.athena_cross_actor_runtime_statistics_read",
    }
    for when, account, region, actor, principal, name, workgroup, qids, record in reads:
        candidates = [item for item in starts
                      if item[1:3] == (account, region)
                      and item[3] != principal
                      and (item[4] == workgroup if name == "ListQueryExecutions" else item[5] in qids)
                      and timedelta(0) <= when - item[0] <= timedelta(hours=1 if name == "ListQueryExecutions" else 24)]
        if not candidates:
            continue
        start = max(candidates, key=lambda x: x[0])
        partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
        target = f"arn:{partition}:athena:{region}:{account}:workgroup/{start[4]}"
        out.append({"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
                    "event.name": "AthenaCrossActor" + name, "event.outcome": "success",
                    "event.id": record["eventID"], "event.time": record["eventTime"],
                    "account.id": account, "actor.id": actor, "target.id": target,
                    flag_by_name[name]: True,
                    "correlation_evidence": {"start_query_event_id": start[6]["eventID"]}})
    return out
