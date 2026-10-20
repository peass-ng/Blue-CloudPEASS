"""Athena workgroup creation, stored-query updates and bounded query join.

CloudTrail masks SQL with ***OMITTED***. SQL, S3 locations, descriptions and
client tokens never enter detection evidence.
"""

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z0-9]+)+-[0-9]\Z")
_WORKGROUP = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_S3 = re.compile(r"s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[A-Za-z0-9!_.*'()/=-]*\Z")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def _common(record: Mapping[str, Any], names: set[str]):
    name = record.get("eventName")
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, identity = record.get("requestParameters"), record.get("userIdentity")
    if (record.get("eventSource") != "athena.amazonaws.com" or name not in names
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(identity, Mapping)
            or identity.get("accountId") not in (None, account)
            or not isinstance(identity.get("arn"), str)
            or not identity["arn"].startswith("arn:")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _time(record.get("eventTime")) is None):
        return None
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    return account, region, partition, identity["arn"], request, _time(record["eventTime"])


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    common = _common(record, {"CreateWorkGroup", "UpdatePreparedStatement", "UpdateNamedQuery"})
    if common is None:
        return None
    account, region, partition, actor, request, _ = common
    flags = {"request.athena_workgroup_result_output_configured": False,
             "request.athena_prepared_statement_updated": False,
             "request.athena_named_query_updated": False}
    if name == "CreateWorkGroup":
        workgroup = request.get("name")
        config = request.get("configuration")
        result = config.get("resultConfiguration") if isinstance(config, Mapping) else None
        location = result.get("outputLocation") if isinstance(result, Mapping) else None
        if (not isinstance(workgroup, str) or not _WORKGROUP.fullmatch(workgroup)
                or not isinstance(location, str) or not _S3.fullmatch(location)):
            return None
        target = f"arn:{partition}:athena:{region}:{account}:workgroup/{workgroup}"
        flags["request.athena_workgroup_result_output_configured"] = True
    elif name == "UpdatePreparedStatement":
        workgroup, statement = request.get("workGroup"), request.get("statementName")
        if (not isinstance(workgroup, str) or not _WORKGROUP.fullmatch(workgroup)
                or not isinstance(statement, str) or not _WORKGROUP.fullmatch(statement)
                or not isinstance(request.get("queryStatement"), str)
                or not request["queryStatement"]):
            return None
        target = f"arn:{partition}:athena:{region}:{account}:workgroup/{workgroup}"
        flags["request.athena_prepared_statement_updated"] = True
    else:
        query_id = request.get("namedQueryId")
        if (not isinstance(query_id, str) or not _UUID.fullmatch(query_id)
                or not isinstance(request.get("name"), str) or not request["name"]
                or not isinstance(request.get("queryString"), str)
                or not request["queryString"]):
            return None
        target = query_id
        flags["request.athena_named_query_updated"] = True
    return {"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
            "event.name": name, "event.outcome": "success",
            "event.id": record["eventID"], "event.time": record["eventTime"],
            "account.id": account, "actor.id": actor, "target.id": target,
            **flags}


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    created = []
    started = []
    for record in records:
        common = _common(record, {"CreateWorkGroup", "StartQueryExecution"})
        if common is None:
            continue
        account, region, partition, actor, request, when = common
        if record["eventName"] == "CreateWorkGroup":
            normalized = normalize(record)
            if normalized is not None:
                created.append((when, account, region, actor, request["name"], normalized["target.id"], record))
            continue
        workgroup = request.get("workGroup")
        response = record.get("responseElements")
        qid = response.get("queryExecutionId") if isinstance(response, Mapping) else None
        if (isinstance(workgroup, str) and _WORKGROUP.fullmatch(workgroup)
                and isinstance(qid, str) and _UUID.fullmatch(qid)):
            started.append((when, account, region, actor, workgroup, record))
    out = []
    for when, account, region, actor, workgroup, record in started:
        prior = [item for item in created if item[1:5] == (account, region, actor, workgroup)
                 and timedelta(0) <= when - item[0] <= timedelta(hours=1)]
        if not prior:
            continue
        item = max(prior, key=lambda x: x[0])
        out.append({"cloud.provider": "aws", "event.source": "athena.amazonaws.com",
                    "event.name": "StartQueryExecutionInNewWorkGroup", "event.outcome": "success",
                    "event.id": record["eventID"], "event.time": record["eventTime"],
                    "account.id": account, "actor.id": actor, "target.id": item[5],
                    "request.athena_new_workgroup_query_started": True,
                    "correlation_evidence": {"create_workgroup_event_id": item[6]["eventID"]}})
    return out
