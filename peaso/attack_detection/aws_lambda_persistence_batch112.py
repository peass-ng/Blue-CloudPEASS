"""Observable Lambda layer and runtime persistence signals from CloudTrail."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_REGION = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_FUNCTION = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_LAYER_NAME = re.compile(r"[A-Za-z0-9_-]{1,140}\Z")
_WINDOW = timedelta(hours=1)


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return result.astimezone(timezone.utc) if result.tzinfo else None


def _base(record: Mapping[str, Any]) -> tuple[str, str, Mapping[str, Any], Mapping[str, Any]] | None:
    account, region = record.get("recipientAccountId"), record.get("awsRegion")
    request, response = record.get("requestParameters"), record.get("responseElements")
    if (record.get("eventSource") != "lambda.amazonaws.com"
            or record.get("eventCategory") != "Management"
            or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True
            or record.get("readOnly") is not False
            or record.get("errorCode") or record.get("errorMessage")
            or not isinstance(record.get("eventID"), str) or not record["eventID"]
            or _when(record.get("eventTime")) is None
            or not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)
            or not isinstance(request, Mapping) or not isinstance(response, Mapping)
            or response.get("errorCode") or response.get("errorMessage")):
        return None
    return account, region, request, response


def _function_name(value: Any, account: str, region: str) -> str | None:
    if not isinstance(value, str):
        return None
    prefix = f"arn:aws:lambda:{region}:{account}:function:"
    name = value[len(prefix):] if value.startswith(prefix) else value
    return name if _FUNCTION.fullmatch(name) else None


def _function(record: Mapping[str, Any], account: str, region: str,
              request: Mapping[str, Any], response: Mapping[str, Any]) -> str | None:
    name = _function_name(request.get("functionName"), account, region)
    expected = f"arn:aws:lambda:{region}:{account}:function:{name}"
    if not name:
        return None
    if record.get("eventName") == "PublishVersion20150331":
        version = response.get("version")
        return name if (isinstance(version, str) and re.fullmatch(r"[1-9][0-9]*", version)
                        and response.get("functionArn") == f"{expected}:{version}") else None
    return name if response.get("functionArn") == expected else None


def _layer(value: Any, region: str) -> tuple[str, str, str] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        rf"arn:aws:lambda:{re.escape(region)}:([0-9]{{12}}):layer:([A-Za-z0-9_-]{{1,140}}):([0-9]+)",
        value)
    return match.groups() if match else None


def _response_layers(response: Mapping[str, Any]) -> set[str]:
    values = response.get("layers")
    if not isinstance(values, list):
        return set()
    return {item["arn"] for item in values
            if isinstance(item, Mapping) and isinstance(item.get("arn"), str)}


def _finding(record: Mapping[str, Any], account: str, target: str,
             name: str, flag: str, prior: str | None = None) -> dict[str, Any]:
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    result = {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": name, "event.outcome": "success",
        "event.id": record["eventID"], "event.time": record["eventTime"],
        "account.id": account, "actor.id": identity.get("arn"),
        "target.id": target, flag: True,
    }
    if prior:
        result["correlation_evidence"] = {"prior_event_id": prior}
    return result


def normalize(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    base = _base(record)
    if base is None:
        return []
    account, region, request, response = base
    name = record.get("eventName")
    if name == "AddLayerVersionPermission20181031":
        layer_name = request.get("layerName")
        version = request.get("versionNumber")
        if (not isinstance(layer_name, str) or not _LAYER_NAME.fullmatch(layer_name)
                or not isinstance(version, int) or isinstance(version, bool) or version < 1
                or request.get("action") != "lambda:GetLayerVersion"
                or request.get("principal") != "*"
                or "organizationId" in request):
            return []
        statement_id = request.get("statementId")
        if not isinstance(statement_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", statement_id):
            return []
        statement_text = response.get("statement")
        if not isinstance(statement_text, str) or len(statement_text) > 8192:
            return []
        try:
            statement = json.loads(statement_text)
        except ValueError:
            return []
        expected_arn = f"arn:aws:lambda:{region}:{account}:layer:{layer_name}:{version}"
        if (not isinstance(statement, Mapping)
                or statement.get("Sid") != statement_id
                or statement.get("Effect") != "Allow"
                or statement.get("Principal") != "*"
                or statement.get("Action") != "lambda:GetLayerVersion"
                or statement.get("Resource") != expected_arn
                or statement.get("Condition")
                or not isinstance(response.get("revisionId"), str)
                or not response["revisionId"]):
            return []
        target = "sha256:" + hashlib.sha256(expected_arn.encode()).hexdigest()[:24]
        return [_finding(record, account, target, name,
                         "request.lambda_public_layer_version_grant")]
    if name == "PublishLayerVersion20181031":
        layer_name = request.get("layerName")
        version_arn = response.get("layerVersionArn")
        parsed = _layer(version_arn, region)
        if (not isinstance(layer_name, str) or not _LAYER_NAME.fullmatch(layer_name)
                or parsed != (account, layer_name, str(response.get("version")))
                or response.get("layerArn") != version_arn.rsplit(":", 1)[0]):
            return []
        return [_finding(record, account, version_arn, "LambdaLayerVersionPublished",
                         "request.lambda_layer_version_published")]
    if name == "UpdateFunctionConfiguration20150331v2":
        function = _function(record, account, region, request, response)
        layers = request.get("layers")
        if (not function or not isinstance(layers, list) or not layers
                or not all(_layer(item, region) for item in layers)
                or not set(layers).issubset(_response_layers(response))):
            return []
        return [_finding(record, account, function, "LambdaLayerSetApplied",
                         "request.lambda_layer_set_applied")]
    if name == "PutRuntimeManagementConfig":
        function = _function(record, account, region, request, response)
        mode = request.get("updateRuntimeOn")
        if not function or mode not in {"FunctionUpdate", "Manual"} or response.get("updateRuntimeOn") != mode:
            return []
        if mode == "Manual":
            arn = request.get("runtimeVersionArn")
            if (not isinstance(arn, str)
                    or not arn.startswith(f"arn:aws:lambda:{region}::runtime:")
                    or response.get("runtimeVersionArn") != arn):
                return []
        synthetic = "LambdaRuntimePinnedManual" if mode == "Manual" else "LambdaRuntimeDeferredUntilFunctionUpdate"
        flag = "request.lambda_runtime_manual" if mode == "Manual" else "request.lambda_runtime_function_update"
        return [_finding(record, account, function, synthetic, flag)]
    return []


def correlate(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Link exact layer ARN publication, attach, config follow-up and snapshot."""
    rows: list[tuple[datetime, Mapping[str, Any], str, str, Mapping[str, Any], Mapping[str, Any]]] = []
    seen: set[str] = set()
    for record in records:
        if record.get("eventName") not in {
                "PublishLayerVersion20181031", "UpdateFunctionConfiguration20150331v2",
                "PublishVersion20150331"}:
            continue
        base = _base(record)
        if base is None or record["eventID"] in seen:
            continue
        account, region, request, response = base
        when = _when(record.get("eventTime"))
        if when is None:
            continue
        seen.add(record["eventID"])
        rows.append((when, record, account, region, request, response))
    # CloudTrail timestamps have second resolution. Publication and attach can
    # share a second, so accept exact ARN equality at that timestamp.
    priority = {"PublishLayerVersion20181031": 0, "UpdateFunctionConfiguration20150331v2": 1,
                "PublishVersion20150331": 2}
    rows.sort(key=lambda row: (row[0], priority[row[1]["eventName"]], row[1]["eventID"]))
    published: dict[str, tuple[datetime, str, str]] = {}
    attached: dict[tuple[str, str, str], tuple[datetime, str, str, set[str]]] = {}
    results: list[dict[str, Any]] = []
    for when, record, account, region, request, response in rows:
        name = record["eventName"]
        identity = record.get("userIdentity")
        actor = identity.get("arn") if isinstance(identity, Mapping) else None
        if not isinstance(actor, str) or not actor:
            continue
        if name == "PublishLayerVersion20181031":
            if normalize(record):
                published[response["layerVersionArn"]] = when, record["eventID"], actor
            continue
        function = _function(record, account, region, request, response)
        if not function:
            continue
        key = account, region, function
        if name == "UpdateFunctionConfiguration20150331v2":
            normalized = normalize(record)
            if normalized:
                layers = set(request["layers"])
                attached[key] = when, record["eventID"], actor, layers
                for layer in layers:
                    prior = published.get(layer)
                    if (prior and prior[2] == actor and timedelta(0) <= when - prior[0] <= _WINDOW):
                        results.append(_finding(record, account, function,
                            "LambdaFreshLayerAttached", "request.lambda_fresh_layer_attached", prior[1]))
                        break
            elif "layers" in request:
                # An accepted empty layer list removes the prior attachment.
                if not _response_layers(response):
                    attached.pop(key, None)
            else:
                prior = attached.get(key)
                if (prior and prior[2] == actor and timedelta(0) <= when - prior[0] <= _WINDOW
                        and prior[3] & _response_layers(response)):
                    results.append(_finding(record, account, function,
                        "LambdaConfigFollowupAfterLayer",
                        "request.lambda_config_followup_after_layer", prior[1]))
            continue
        prior = attached.get(key)
        version = response.get("version")
        if (prior and prior[2] == actor and timedelta(0) <= when - prior[0] <= _WINDOW
                and isinstance(version, str) and re.fullmatch(r"[1-9][0-9]*", version)
                and prior[3] & _response_layers(response)):
            results.append(_finding(record, account, f"{function}:{version}",
                "LambdaLayerSnapshottedInVersion",
                "request.lambda_layer_snapshotted_version", prior[1]))
    return results
