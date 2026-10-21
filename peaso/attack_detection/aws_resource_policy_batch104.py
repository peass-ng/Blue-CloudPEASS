"""Bounded resource-policy principal-validation pairs and DynamoDB read grant."""

from collections.abc import Iterable, Mapping
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_PRINCIPAL = re.compile(r"arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:(?:user|role)/[^\s*]+\Z")
_SPECS = {
    "kinesis.amazonaws.com": ("PutResourcePolicy", "policy", "resourceARN"),
    "codeartifact.amazonaws.com": ("PutDomainPermissionsPolicy", "policyDocument", "domain"),
    "s3tables.amazonaws.com": ("PutTableBucketPolicy", "resourcePolicy", "tableBucketARN"),
    "s3vectors.amazonaws.com": ("PutVectorBucketPolicy", "policy", "vectorBucketArn"),
    "aps.amazonaws.com": ("PutResourcePolicy", "policyDocument", "workspaceId"),
}


def _obj(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _valid(record: Mapping[str, Any], source: str, name: str) -> tuple | None:
    if (record.get("eventSource") != source or record.get("eventName") != name
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = _obj(record.get("userIdentity"))
    request = record.get("requestParameters")
    actor = identity.get("arn")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or identity.get("accountId") != account
            or not isinstance(region, str) or not region
            or not isinstance(actor, str) or not actor
            or not isinstance(request, Mapping)
            or not isinstance(record.get("eventID"), str) or not record["eventID"]):
        return None
    return account, region, actor, request


def _policy(value: Any) -> tuple[str, str, str, set[str]] | None:
    if not isinstance(value, str) or not 0 < len(value) <= 65536:return None
    try:document = json.loads(value)
    except (ValueError, TypeError):return None
    if not isinstance(document, dict) or document.get("Version") != "2012-10-17":return None
    statements = document.get("Statement")
    if isinstance(statements, dict):statements = [statements]
    if not isinstance(statements, list) or len(statements) != 1 or not isinstance(statements[0], dict):return None
    statement = statements[0]
    if statement.get("Effect") != "Allow":return None
    principal = _obj(statement.get("Principal")).get("AWS")
    resource = statement.get("Resource")
    if (not isinstance(principal, str) or not _PRINCIPAL.fullmatch(principal)
            or not isinstance(resource, str) or not resource.startswith("arn:aws")):
        return None
    action = statement.get("Action")
    actions = {action} if isinstance(action, str) else set(action) if isinstance(action, list) and all(isinstance(x, str) for x in action) else set()
    if not actions:return None
    comparable = deepcopy(document)
    if isinstance(comparable["Statement"], dict):comparable["Statement"]["Principal"] = {"AWS":"<principal>"}
    else:comparable["Statement"][0]["Principal"] = {"AWS":"<principal>"}
    return principal, resource, json.dumps(comparable,sort_keys=True,separators=(",", ":")), actions


def _target(source: str, account: str, region: str, request: Mapping[str, Any]) -> str | None:
    value = request.get(_SPECS[source][2])
    if source == "codeartifact.amazonaws.com":
        return f"arn:aws:codeartifact:{region}:{account}:domain/{value}" if isinstance(value, str) and value else None
    if source == "aps.amazonaws.com":
        return f"arn:aws:aps:{region}:{account}:workspace/{value}" if isinstance(value, str) and value else None
    return value if isinstance(value, str) and value.startswith("arn:aws:") else None


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except ValueError:return None


def correlate_validation(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    writes=[]
    for record in records:
        source = record.get("eventSource")
        if source not in _SPECS:continue
        name, body_key, _ = _SPECS[source]
        parsed = _valid(record, source, name)
        if parsed is None:continue
        account, region, actor, request = parsed
        target = _target(source, account, region, request)
        policy = _policy(request.get(body_key))
        when = _when(record.get("eventTime"))
        if target is None or policy is None or when is None or policy[1] != target:continue
        error = record.get("errorCode")
        if error and error not in {"ValidationException", "InvalidArgumentException", "BadRequestException", "InvalidParameterException"}:continue
        response = _obj(record.get("responseElements"))
        if not error and (record.get("errorMessage") or response.get("errorCode") or response.get("errorMessage")):continue
        writes.append((when, source, account, actor, target, policy[0], policy[2], bool(error), record))
    accepted={}
    result=[]
    for when,source,account,actor,target,principal,body,failed,record in writes:
        key=(source,account,actor,target,body)
        if not failed:accepted.setdefault(key,[]).append((when,principal,record["eventID"]))
    for when,source,account,actor,target,principal,body,failed,record in writes:
        if not failed:continue
        key=(source,account,actor,target,body)
        controls=[x for x in accepted.get(key,[]) if x[1]!=principal and abs(when-x[0])<=timedelta(minutes=15)]
        if not controls:continue
        control=min(controls,key=lambda x:abs(when-x[0]))
        result.append({"cloud.provider":"aws", "event.source":source,
                       "event.name":"ResourcePolicyPrincipalValidationProbe", "event.outcome":"failure",
                       "event.id":record["eventID"], "event.time":record.get("eventTime"),
                       "account.id":account, "actor.id":actor, "target.id":target,
                       "request.resource_policy_principal_validation_pair":True,
                       "correlation_evidence":{"accepted_event_id":control[2]}})
    return result


def normalize_dynamodb_grant(record: Mapping[str, Any]) -> dict[str, Any] | None:
    parsed=_valid(record,"dynamodb.amazonaws.com","PutResourcePolicy")
    if parsed is None or record.get("errorCode") or record.get("errorMessage"):return None
    account,region,actor,request=parsed
    target=request.get("resourceArn")
    p=_policy(request.get("policy"))
    response=_obj(record.get("responseElements"))
    if (not isinstance(target,str) or not target.startswith(f"arn:aws:dynamodb:{region}:{account}:table/")
            or p is None or p[1]!=target or "dynamodb:GetItem" not in p[3]
            or not isinstance(response.get("revisionId"),str) or not response["revisionId"]):return None
    return {"cloud.provider":"aws","event.source":"dynamodb.amazonaws.com",
            "event.name":"PutResourcePolicy","event.outcome":"success",
            "event.id":record["eventID"],"event.time":record.get("eventTime"),
            "account.id":account,"actor.id":actor,"target.id":target,
            "request.dynamodb_table_getitem_principal_granted":True}
