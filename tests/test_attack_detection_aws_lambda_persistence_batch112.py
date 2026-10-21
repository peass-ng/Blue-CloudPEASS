"""Synthetic derivatives of the isolated Lambda layer and runtime lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
FUNCTION = "synthetic-lambda"
FUNCTION_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION}"
LAYER = f"arn:aws:lambda:{REGION}:{ACCOUNT}:layer:synthetic-layer"
LAYER_VERSION = LAYER + ":1"
RUNTIME = f"arn:aws:lambda:{REGION}::runtime:" + "a" * 64
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"
IDS = {
    "aws-lambda-layer-version-published",
    "aws-lambda-layer-set-applied",
    "aws-lambda-fresh-layer-attached",
    "aws-lambda-config-followup-after-layer",
    "aws-lambda-layer-snapshotted-version",
    "aws-lambda-runtime-function-update",
    "aws-lambda-runtime-manual",
    "aws-lambda-alias-low-weight-version",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 8
    return selected


def event(name, second, request, response, *, error=None, actor=ACTOR):
    result = {
        "eventSource": "lambda.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"77777777-7777-4777-8777-{second:012d}",
        "eventTime": f"2026-10-21T08:10:{second:02d}Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": actor},
        "requestParameters": request, "responseElements": response,
    }
    if error:
        result["errorCode"] = error
    return result


def sample():
    return [
        event("PublishLayerVersion20181031", 0,
              {"layerName": "synthetic-layer", "content": {}, "compatibleRuntimes": ["python3.12"]},
              {"layerArn": LAYER, "layerVersionArn": LAYER_VERSION, "version": 1}),
        event("UpdateFunctionConfiguration20150331v2", 1,
              {"functionName": FUNCTION, "environment": {}, "layers": [LAYER_VERSION]},
              {"functionArn": FUNCTION_ARN, "layers": [{"arn": LAYER_VERSION}],
               "codeSha256": "synthetic-code-hash"}),
        event("UpdateFunctionConfiguration20150331v2", 3,
              {"functionName": FUNCTION, "environment": {}},
              {"functionArn": FUNCTION_ARN, "layers": [{"arn": LAYER_VERSION}]}),
        event("PublishVersion20150331", 5,
              {"functionName": FUNCTION, "description": "synthetic wrapper version"},
              {"functionArn": FUNCTION_ARN + ":1", "version": "1",
               "layers": [{"arn": LAYER_VERSION}]}),
        event("UpdateFunctionConfiguration20150331v2", 7,
              {"functionName": FUNCTION, "environment": {}, "layers": []},
              {"functionArn": FUNCTION_ARN}),
        event("PublishVersion20150331", 9,
              {"functionName": FUNCTION},
              {"functionArn": FUNCTION_ARN + ":2", "version": "2"}),
        event("CreateAlias20150331", 11,
              {"functionName": FUNCTION, "name": "stable", "functionVersion": "2"},
              {"aliasArn": FUNCTION_ARN + ":stable", "functionVersion": "2"}),
        event("UpdateAlias20150331", 13,
              {"functionName": FUNCTION, "name": "stable", "functionVersion": "2",
               "routingConfig": {"additionalVersionWeights": {"1": 0.01}}},
              {"aliasArn": FUNCTION_ARN + ":stable", "functionVersion": "2",
               "routingConfig": {"additionalVersionWeights": {"1": 0.01}}}),
        event("PutRuntimeManagementConfig", 15,
              {"functionName": FUNCTION, "updateRuntimeOn": "FunctionUpdate"},
              {"functionArn": FUNCTION_ARN, "updateRuntimeOn": "FunctionUpdate"}),
        event("PutRuntimeManagementConfig", 17,
              {"functionName": FUNCTION, "updateRuntimeOn": "Manual",
               "runtimeVersionArn": RUNTIME},
              {"functionArn": FUNCTION_ARN, "updateRuntimeOn": "Manual",
               "runtimeVersionArn": RUNTIME}),
    ]


def hits(events):
    return [finding.technique_id for finding in detect_aws_events(events, rules())]


def test_live_shaped_sequence_matches_observable_routes():
    assert set(hits(sample())) == IDS
    assert len(hits(sample())) == 8


def test_wrapper_key_is_not_claimed_from_redacted_cloudtrail():
    rows = sample()
    assert rows[1]["requestParameters"]["environment"] == {}
    assert rows[2]["requestParameters"]["environment"] == {}
    assert "AWS_LAMBDA_EXEC_WRAPPER" not in str(rows)
    assert "aws-lambda-config-followup-after-layer" in hits(rows)


def test_failed_and_unrelated_layer_requests_do_not_form_chain():
    rows = sample()
    rows[0]["errorCode"] = "AccessDeniedException"
    assert "aws-lambda-layer-version-published" not in hits(rows)
    assert "aws-lambda-fresh-layer-attached" not in hits(rows)
    rows = sample()
    rows[1]["responseElements"]["layers"] = []
    assert "aws-lambda-layer-set-applied" not in hits(rows)
    assert "aws-lambda-fresh-layer-attached" not in hits(rows)
    rows = sample()
    rows[1]["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other-actor"
    assert "aws-lambda-fresh-layer-attached" not in hits(rows)
    assert "aws-lambda-config-followup-after-layer" not in hits(rows)


def test_runtime_modes_require_matching_success_response():
    rows = sample()
    rows[-1]["responseElements"]["runtimeVersionArn"] = RUNTIME[:-1] + "b"
    assert "aws-lambda-runtime-manual" not in hits(rows)
    rows = sample()
    rows[-2]["readOnly"] = True
    assert "aws-lambda-runtime-function-update" not in hits(rows)


def test_version_snapshot_requires_same_layer_and_deduplicates_input():
    rows = sample()
    doubled = hits(rows + deepcopy(rows))
    assert doubled.count("aws-lambda-fresh-layer-attached") == 1
    assert doubled.count("aws-lambda-layer-snapshotted-version") == 1
    rows[3]["responseElements"]["layers"] = []
    assert "aws-lambda-layer-snapshotted-version" not in hits(rows)


def test_layer_removal_before_followup_clears_correlation():
    rows = sample()
    rows[2], rows[4] = rows[4], rows[2]
    rows[2]["eventTime"] = "2026-10-21T08:10:02Z"
    rows[4]["eventTime"] = "2026-10-21T08:10:07Z"
    assert "aws-lambda-config-followup-after-layer" not in hits(rows)
    assert "aws-lambda-layer-snapshotted-version" not in hits(rows)
