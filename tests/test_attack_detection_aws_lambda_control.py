"""Lambda control signals use exact API names, values and accepted requests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_lambda_control import normalize_aws_lambda_control


def record(name: str, request: dict) -> dict:
    return {
        "eventSource": "lambda.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "3570eca4-5356-48f2-9c1e-3a980fa78cbc",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"functionName": "disposable-function", **request},
        "responseElements": None,
    }


@pytest.mark.parametrize("name,params,field", [
    ("PutFunctionConcurrency20171031", {"reservedConcurrentExecutions": 0},
     "request.zero_reserved_concurrency"),
    ("PutFunctionRecursionConfig", {"recursiveLoop": "Allow"},
     "request.recursive_loop_allowed"),
    ("CreateFunctionUrlConfig", {"authType": "NONE"},
     "request.function_url_auth_none"),
    ("UpdateFunctionUrlConfig", {"authType": "NONE"},
     "request.function_url_auth_none"),
    ("AddPermission20150331v2", {"principal": "*", "action": "lambda:InvokeFunctionUrl",
                                    "functionUrlAuthType": "NONE"},
     "request.public_function_url_grant"),
    ("DeleteFunction20150331", {}, "request.function_deleted"),
])
def test_exact_success_signal_and_denied_negative(name, params, field):
    event = record(name, params)
    rule = Rule("unit", "Lambda unit", "high", "Accepted write", "unit", "aws",
                {"event.source": "lambda.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    hits = detect_aws_events([event], [rule])
    assert len(hits) == 1
    assert hits[0].target_id == "arn:aws:lambda:us-east-1:123456789012:function:disposable-function"
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([denied], [rule]) == []


@pytest.mark.parametrize("name,params", [
    ("PutFunctionConcurrency", {"reservedConcurrentExecutions": 0}),
    ("PutFunctionConcurrency20171031", {"reservedConcurrentExecutions": False}),
    ("PutFunctionConcurrency20171031", {"reservedConcurrentExecutions": 1}),
    ("PutFunctionRecursionConfig", {"recursiveLoop": "Terminate"}),
    ("CreateFunctionUrlConfig", {"authType": "AWS_IAM"}),
    ("AddPermission20150331v2", {"principal": "123456789012", "action": "lambda:InvokeFunctionUrl",
                                    "functionUrlAuthType": "NONE"}),
    ("AddPermission20150331v2", {"principal": "*", "action": "lambda:InvokeFunction",
                                    "functionUrlAuthType": "NONE"}),
    ("RemovePermission20150331v2", {}),
])
def test_no_generic_or_restoration_signal(name, params):
    assert normalize_aws_lambda_control(record(name, params)) is None


def test_invalid_target_and_incomplete_event():
    wrong = record("DeleteFunction20150331", {})
    wrong["recipientAccountId"] = "999999999999"
    assert normalize_aws_lambda_control(wrong) is None
    missing_response = record("DeleteFunction20150331", {})
    del missing_response["responseElements"]
    assert normalize_aws_lambda_control(missing_response) is None
    invalid_function = record("DeleteFunction20150331", {"functionName": "invalid:name"})
    assert normalize_aws_lambda_control(invalid_function) is None
