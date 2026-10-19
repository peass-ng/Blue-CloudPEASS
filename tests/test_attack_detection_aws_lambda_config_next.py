"""Lambda configuration predicates against observed CloudTrail shapes."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="layer", title="External layer", level="medium", description="layer",
         technique_id="aws-lambda-external-layer-attached", product="aws",
         selection={"event.source": "lambda.amazonaws.com",
                    "event.name": "UpdateFunctionConfiguration20150331v2", "event.outcome": "success",
                    "request.lambda_external_layer_attached": True}),
    Rule(id="alias", title="Alias split", level="low", description="alias",
         technique_id="aws-lambda-alias-low-weight-version", product="aws",
         selection={"event.source": "lambda.amazonaws.com",
                    "event.name": "UpdateAlias20150331", "event.outcome": "success",
                    "request.lambda_alias_low_weight_version": True}),
    Rule(id="dest", title="External destination", level="medium", description="destination",
         technique_id="aws-lambda-external-async-destination", product="aws",
         selection={"event.source": "lambda.amazonaws.com",
                    "event.name": ["PutFunctionEventInvokeConfig", "UpdateFunctionEventInvokeConfig"],
                    "event.outcome": "success", "request.lambda_external_async_destination": True}),
]


def _event(name: str, request: dict) -> dict:
    return {"eventSource": "lambda.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "222233334444", "requestParameters": request}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_external_layer_differs_from_local_layer() -> None:
    event = _event("UpdateFunctionConfiguration20150331v2", {
        "functionName": "synthetic", "environment": {},
        "layers": ["arn:aws:lambda:us-east-1:222233334444:layer:synthetic:1"]})
    assert _hits(event) == []
    event["requestParameters"]["layers"][0] = "arn:aws:lambda:us-east-1:111122223333:layer:synthetic:1"
    assert _hits(event) == ["aws-lambda-external-layer-attached"]
    event["errorCode"] = "AccessDeniedException"
    assert _hits(event) == []


def test_small_alias_weight_and_reset() -> None:
    event = _event("UpdateAlias20150331", {"functionName": "synthetic", "name": "canary",
                   "routingConfig": {"additionalVersionWeights": {"2": 0.01}}})
    assert _hits(event) == ["aws-lambda-alias-low-weight-version"]
    for weights in ({}, {"2": 0}, {"2": 0.5}):
        item = deepcopy(event)
        item["requestParameters"]["routingConfig"]["additionalVersionWeights"] = weights
        assert _hits(item) == []


def test_external_async_destination_and_failed_request() -> None:
    event = _event("PutFunctionEventInvokeConfig", {"functionName": "synthetic",
                   "destinationConfig": {"onSuccess": {"destination":
                       "arn:aws:sqs:us-east-1:222233334444:synthetic"}}})
    assert _hits(event) == []
    event["requestParameters"]["destinationConfig"]["onSuccess"]["destination"] = (
        "arn:aws:sqs:us-east-1:111122223333:synthetic")
    assert _hits(event) == ["aws-lambda-external-async-destination"]
    event["errorCode"] = "InvalidParameterValueException"
    assert _hits(event) == []
