"""A MicroVM shell route needs a globally authorized connector pass."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-lambda-microvm-passrole-runmicrovm-shell"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
IMAGE = "arn:aws:lambda:us-east-1:111111111111:microvm-image:ready"
CONNECTOR = "arn:aws:lambda:us-east-1:aws:network-connector:aws-network-connector:SHELL_INGRESS"


def _case(connector_resource="*", connector_region=None):
    snap = _snapshot(ENTRY)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    statements = [
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
        {"Effect": "Allow", "Action": ["lambda:RunMicrovm", "lambda:CreateMicrovmShellAuthToken"],
         "Resource": IMAGE},
        {"Effect": "Allow", "Action": "lambda:PassNetworkConnector", "Resource": connector_resource},
    ]
    if connector_region:
        statements[-1]["Condition"] = {"StringEquals": {"aws:RequestedRegion": connector_region}}
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = statements
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": ["sts:AssumeRole", "sts:TagSession"]}]
    snap["collections"].append({"type": "lambda_microvm_image", "scope": "111111111111/us-east-1",
                                "service": "lambda-microvms", "status": "collected", "error": None,
                                "items": [{"imageArn": IMAGE, "state": "CREATED",
                                           "latestActiveImageVersion": "1"}]})
    return snap


def _definite(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_global_connector_permission_allows_conditional_route():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_connector_arn_scoped_permission_does_not_authorize_resource_less_action():
    assert TARGET not in _definite(_case(CONNECTOR))


def test_connector_requested_region_must_match_image_region():
    assert _definite(_case("*", "us-east-1")) == {TARGET: "conditional"}
    assert TARGET not in _definite(_case("*", "us-west-2"))


def test_scoped_deny_does_not_block_resource_less_connector_action():
    snap = _case()
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Deny", "Action": "lambda:PassNetworkConnector", "Resource": CONNECTOR})
    assert _definite(snap) == {TARGET: "conditional"}


def test_managed_base_image_possibility_is_unknown_without_runtime_evidence():
    snap = _case()
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"][1]["Resource"] = "*"
    image_collection = next(c for c in snap["collections"] if c["type"] == "lambda_microvm_image")
    image_collection["items"] = []
    assert TARGET not in _definite(snap)
    members = reached(privesc.analyze(snap, entries=[ENTRY], include_unknown=True), SOURCE, ID)
    assert any(name.startswith("unresolved:") and confidence == "unknown"
               for name, confidence in members.items())
