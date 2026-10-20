"""Lambda read, log routing, and event source mapping signals from CloudTrail."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
import re
from typing import Any

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}-[a-z]+-\d\Z")
_FUNCTION = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_LAYER = re.compile(r"[A-Za-z0-9_-]{1,140}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_LOG_GROUP = re.compile(r"[A-Za-z0-9_./#-]{1,512}\Z")
_READ_FLAGS = {
    "ListFunctions20150331": "request.lambda_functions_listed",
    "ListVersionsByFunction20150331": "request.lambda_versions_listed",
    "GetFunction20150331v2": "request.lambda_function_package_requested",
    "GetFunctionConfiguration20150331v2": "request.lambda_function_configuration_read",
    "GetLayerVersion20181031": "request.lambda_layer_package_requested",
}
_WRITE_FLAGS = {
    "UpdateFunctionConfiguration20150331v2": "request.lambda_log_group_redirected",
    "CreateEventSourceMapping20150331": "request.lambda_event_source_mapping_created",
    "UpdateEventSourceMapping20150331": "request.lambda_event_source_mapping_target_submitted",
}


def _common(record: Mapping[str, Any], read: bool):
    if (record.get("eventSource") != "lambda.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not read
            or record.get("errorCode") or record.get("errorMessage")):
        return None
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    identity = record.get("userIdentity")
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("arn"), str)
            or identity.get("accountId") not in (None, account)
            or not isinstance(record.get("eventID"), str)
            or not record["eventID"]):
        return None
    try:
        when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            return None
    except (KeyError, AttributeError, ValueError):
        return None
    return account, region, identity["arn"], when


def _function_arn(value: Any, region: str, account: str) -> str | None:
    if not isinstance(value, str):
        return None
    if value.startswith("arn:aws:lambda:"):
        prefix = f"arn:aws:lambda:{region}:{account}:function:"
        if not value.startswith(prefix):
            return None
        name = value[len(prefix):].split(":")[0]
    else:
        name = value
    return f"arn:aws:lambda:{region}:{account}:function:{name}" if _FUNCTION.fullmatch(name) else None


def _mapping_response(response: Any, account: str, region: str):
    if not isinstance(response, Mapping):
        return None
    uuid = response.get("uUID")
    if not isinstance(uuid, str) or not _UUID.fullmatch(uuid):
        return None
    arn = f"arn:aws:lambda:{region}:{account}:event-source-mapping:{uuid}"
    if response.get("eventSourceMappingArn") != arn:
        return None
    function_arn = _function_arn(response.get("functionArn"), region, account)
    source_arn = response.get("eventSourceArn")
    if function_arn != response.get("functionArn") or not isinstance(source_arn, str):
        return None
    parts = source_arn.split(":", 5)
    if (len(parts) != 6 or parts[0:2] != ["arn", "aws"]
            or parts[2] not in {"sqs", "kinesis", "dynamodb", "kafka", "mq", "rds", "docdb"}
            or parts[3] != region or not parts[4] or not parts[5]):
        return None
    return uuid, arn, function_arn, source_arn


def _event(record: Mapping[str, Any], account: str, actor: str,
           target: str, flag: str):
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": record["eventName"], "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": actor, "target.id": target,
        flag: True,
    }


def normalize(record: Mapping[str, Any]) -> dict[str, Any] | None:
    name = record.get("eventName")
    if not isinstance(name, str):
        return None
    if name in _READ_FLAGS:
        read = True
    elif name in _WRITE_FLAGS:
        read = False
    else:
        return None
    common = _common(record, read)
    if common is None:
        return None
    account, region, actor, _when = common
    request, response = record.get("requestParameters"), record.get("responseElements")

    if name == "ListFunctions20150331":
        # The observed successful event had null request and response bodies.
        if request not in (None, {}):
            return None
        return _event(record, account, actor,
                      f"arn:aws:lambda:{region}:{account}:function:*", _READ_FLAGS[name])
    if name in {
        "ListVersionsByFunction20150331", "GetFunction20150331v2",
        "GetFunctionConfiguration20150331v2",
    }:
        if not isinstance(request, Mapping):
            return None
        target = _function_arn(request.get("functionName"), region, account)
        if target is None:
            return None
        return _event(record, account, actor, target, _READ_FLAGS[name])
    if name == "GetLayerVersion20181031":
        if not isinstance(request, Mapping):
            return None
        layer, version = request.get("layerName"), request.get("versionNumber")
        if (not isinstance(layer, str) or not _LAYER.fullmatch(layer)
                or type(version) is not int or version < 1):
            return None
        target = f"arn:aws:lambda:{region}:{account}:layer:{layer}:{version}"
        return _event(record, account, actor, target, _READ_FLAGS[name])
    if name == "UpdateFunctionConfiguration20150331v2":
        if not isinstance(request, Mapping) or not isinstance(response, Mapping):
            return None
        target = _function_arn(request.get("functionName"), region, account)
        config, returned = request.get("loggingConfig"), response.get("loggingConfig")
        if (target is None or response.get("functionArn") != target
                or not isinstance(config, Mapping) or not isinstance(returned, Mapping)):
            return None
        group = config.get("logGroup")
        function_name = target.rsplit(":", 1)[-1]
        if (not isinstance(group, str) or not _LOG_GROUP.fullmatch(group)
                or group == f"/aws/lambda/{function_name}"
                or returned.get("logGroup") != group):
            return None
        event = _event(record, account, actor, target, _WRITE_FLAGS[name])
        event["request.lambda_log_group"] = group
        return event
    if name in {"CreateEventSourceMapping20150331", "UpdateEventSourceMapping20150331"}:
        if not isinstance(request, Mapping):
            return None
        mapping = _mapping_response(response, account, region)
        if mapping is None:
            return None
        uuid, mapping_arn, function_arn, source_arn = mapping
        if _function_arn(request.get("functionName"), region, account) != function_arn:
            return None
        if name == "CreateEventSourceMapping20150331":
            if request.get("eventSourceArn") != source_arn:
                return None
        elif request.get("uUID") != uuid:
            return None
        event = _event(record, account, actor, mapping_arn, _WRITE_FLAGS[name])
        event["request.lambda_mapping_function"] = function_arn
        event["request.lambda_mapping_source"] = source_arn
        return event
    return None


def correlate_repoint(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    created = {}
    updates = []
    deleted = []
    for record in records:
        name = record.get("eventName")
        if name == "CreateEventSourceMapping20150331":
            event = normalize(record)
            if event is not None:
                when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
                created.setdefault(event["target.id"], []).append((when, event, record))
        elif name == "UpdateEventSourceMapping20150331":
            event = normalize(record)
            if event is not None:
                when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
                updates.append((when, event, record))
        elif name == "DeleteEventSourceMapping20150331" and _common(record, False) is not None:
            request = record.get("requestParameters")
            if isinstance(request, Mapping) and isinstance(request.get("uUID"), str):
                when = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
                deleted.append((when, request["uUID"], record["recipientAccountId"], record["awsRegion"]))
    output = []
    for when, update, record in updates:
        for earlier, create, _ in created.get(update["target.id"], []):
            if (not earlier <= when <= earlier + timedelta(minutes=30)
                    or create["account.id"] != update["account.id"]
                    or create["actor.id"] != update["actor.id"]
                    or create["request.lambda_mapping_source"] != update["request.lambda_mapping_source"]
                    or create["request.lambda_mapping_function"] == update["request.lambda_mapping_function"]):
                continue
            uuid = update["target.id"].rsplit(":", 1)[-1]
            if any(earlier < cut < when and uid == uuid and acct == update["account.id"]
                   and region == record["awsRegion"] for cut, uid, acct, region in deleted):
                continue
            event = _event(record, update["account.id"], update["actor.id"],
                           update["target.id"], "request.lambda_mapping_function_repointed")
            event["event.name"] = "LambdaEventSourceMappingFunctionRepointed"
            event["correlation_evidence"] = {
                "create_event_id": create["event.id"],
                "update_event_id": update["event.id"],
                "prior_function": create["request.lambda_mapping_function"],
                "new_function": update["request.lambda_mapping_function"],
                "event_source": update["request.lambda_mapping_source"],
            }
            output.append(event)
            break
    return output
