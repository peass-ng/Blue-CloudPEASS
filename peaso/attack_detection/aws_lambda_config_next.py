"""Lambda wrapper, layer, alias routing and async destination changes."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def _external_layer(value: Any, account: str) -> bool:
    if not isinstance(value, list):
        return False
    for layer in value:
        arn = layer if isinstance(layer, str) else layer.get("arn") if isinstance(layer, Mapping) else None
        if isinstance(arn, str):
            match = re.fullmatch(r"arn:aws:lambda:[a-z0-9-]+:(\d{12}):layer:[A-Za-z0-9_-]+:\d+", arn)
            if match and match.group(1) != account:
                return True
    return False


def _low_weight(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    weights = value.get("additionalVersionWeights")
    return isinstance(weights, Mapping) and any(
        isinstance(version, str) and re.fullmatch(r"\d+", version)
        and type(weight) in (int, float) and 0 < weight <= 0.1
        for version, weight in weights.items())


def _external_async_destination(value: Any, account: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    for key in ("onSuccess", "onFailure", "OnSuccess", "OnFailure"):
        part = value.get(key)
        arn = part.get("destination") or part.get("Destination") if isinstance(part, Mapping) else None
        if isinstance(arn, str):
            match = re.fullmatch(r"arn:aws:(?:sqs|sns|lambda|events):[a-z0-9-]+:(\d{12}):.+", arn)
            if match and match.group(1) != account:
                return True
    return False


def normalize_aws_lambda_config(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "lambda.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"UpdateFunctionConfiguration20150331v2", "UpdateAlias20150331",
                    "PutFunctionEventInvokeConfig", "UpdateFunctionEventInvokeConfig"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    function = request.get("functionName")
    if not isinstance(function, str) or not function:
        return None
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    account = record.get("recipientAccountId") or identity.get("accountId")
    if not isinstance(account, str) or re.fullmatch(r"\d{12}", account) is None:
        return None
    failed = bool(record.get("errorCode") or record.get("errorMessage"))
    return {
        "cloud.provider": "aws", "event.source": "lambda.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": account, "actor.id": identity.get("arn"), "target.id": function,
        "request.lambda_external_layer_attached": (
            not failed and name == "UpdateFunctionConfiguration20150331v2"
            and _external_layer(request.get("layers"), account)
        ),
        "request.lambda_alias_low_weight_version": (
            not failed and name == "UpdateAlias20150331" and _low_weight(request.get("routingConfig"))
        ),
        "request.lambda_external_async_destination": (
            not failed and name in {"PutFunctionEventInvokeConfig", "UpdateFunctionEventInvokeConfig"}
            and _external_async_destination(request.get("destinationConfig"), account)
        ),
    }
