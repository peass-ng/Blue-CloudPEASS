"""A Lambda role swap needs a chosen-code path on the same function."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-lambda-passrole-updatefunctionconfiguration-role-swap"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
FUNCTION = "arn:aws:lambda:us-east-1:111111111111:function:existing"
LAYER = "arn:aws:lambda:us-east-1:111111111111:layer:wrapper"


def _case(*, code=False, layer=True, read_layer=True, layer_name=LAYER, kms=False):
    snap = _snapshot(ENTRY)
    source = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    statements = [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"},
                       "ArnEquals": {"iam:AssociatedResourceArn": FUNCTION}}},
        {"Effect": "Allow", "Action": ["lambda:UpdateFunctionConfiguration", "lambda:InvokeFunction"],
         "Resource": FUNCTION},
    ]
    if code:
        statements.append({"Effect": "Allow", "Action": "lambda:UpdateFunctionCode", "Resource": FUNCTION})
    if layer:
        statements.append({"Effect": "Allow", "Action": "lambda:PublishLayerVersion",
                           "Resource": layer_name})
    if read_layer:
        statements.append({"Effect": "Allow", "Action": "lambda:GetLayerVersion",
                           "Resource": LAYER + ":*"})
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"}]
    config = {"collection_status": "collected", "FunctionArn": FUNCTION,
              "Role": "arn:aws:iam::111111111111:role/old", "PackageType": "Zip",
              "Runtime": "python3.12", "State": "Active", "LastUpdateStatus": "Successful"}
    if kms:
        config["KMSKeyArn"] = "arn:aws:kms:us-east-1:111111111111:key/1234"
    snap["collections"].append({"type": "lambda_function", "scope": "111111111111/us-east-1",
                                "service": "lambda", "status": "collected", "error": None,
                                "items": [{"FunctionName": "existing", "FunctionArn": FUNCTION,
                                           "Role": config["Role"], "Configuration": config,
                                           "Concurrency": {"collection_status": "collected",
                                                           "ReservedConcurrentExecutions": 1},
                                           "CodeSigning": {"collection_status": "collected",
                                                           "CodeSigningConfigArn": "",
                                                           "_request": {"FunctionName": "existing"}}}]})
    return snap


def _definite(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_code_update_role_swap_remains_possible():
    assert _definite(_case(code=True, layer=False, read_layer=False)) == {TARGET: "conditional"}


def test_new_wrapper_layer_can_execute_without_code_update():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_wrapper_needs_same_published_readable_layer():
    assert TARGET not in _definite(_case(read_layer=False))
    assert TARGET not in _definite(_case(layer_name=LAYER.replace("wrapper", "other")))


def test_customer_kms_setting_keeps_wrapper_path_unresolved():
    assert TARGET not in _definite(_case(kms=True))
