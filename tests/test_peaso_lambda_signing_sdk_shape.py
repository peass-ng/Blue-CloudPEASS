"""Native Lambda signing response shape through the collector and production engine."""
from __future__ import annotations

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws, aws_facts_swc
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
NAME = "sample"
ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}"
CONFIG_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:code-signing-config:csc-1"
CID = "aws_lambda_code_signing_configured"


def finding(monkeypatch, response, config=None, *, error=None, state="Active"):
    session = boto3.Session(aws_access_key_id="INERT", aws_secret_access_key="INERT", region_name=REGION)
    client = session.client("lambda", region_name=REGION)
    monkeypatch.setattr(aws.Requests, "client", lambda self, _session, service, region: client)
    with Stubber(client) as stub:
        if error:
            stub.add_client_error("get_function_code_signing_config", error, expected_params={"FunctionName": NAME})
        else:
            stub.add_response("get_function_code_signing_config", response, {"FunctionName": NAME})
        if response and response.get("CodeSigningConfigArn") and not error:
            stub.add_response("get_code_signing_config", config, {"CodeSigningConfigArn": CONFIG_ARN})
        row = {"FunctionName": NAME, "FunctionArn": ARN, "Configuration": {"State": state}}
        enriched = aws_facts_swc._lambda(aws.Requests({"retry_attempts": 1}), session, REGION, [row])[0]
        snapshot = make_snapshot("aws", [SCOPE], [{"type": "lambda_function", "scope": SCOPE,
            "service": "lambda", "status": "collected", "items": [enriched]}],
            created_at="2026-10-18T00:00:00+00:00")
        matches = [f for f in evaluate_snapshot(snapshot, checks=[CID])["findings"] if f["check_id"] == CID]
        assert len(matches) == 1
        stub.assert_no_pending_responses()
        return matches[0]["status"], enriched


def config(*, policy="Enforce", publishers=None):
    if publishers is None:
        publishers = [f"arn:aws:signer:{REGION}:{ACCOUNT}:/signing-profiles/p/1"]
    return {"CodeSigningConfig": {"CodeSigningConfigId": "csc-1", "CodeSigningConfigArn": CONFIG_ARN,
        "LastModified": "2026-10-18T00:00:00.000+0000", "AllowedPublishers": {"SigningProfileVersionArns": publishers},
        "CodeSigningPolicies": {"UntrustedArtifactOnDeployment": policy}}}


def test_sdk_function_name_binds_signing_config(monkeypatch):
    status, row = finding(monkeypatch, {"FunctionName": NAME, "CodeSigningConfigArn": CONFIG_ARN}, config())
    assert status == "PASS"
    assert row["CodeSigning"]["FunctionName"] == NAME
    assert "FunctionArn" not in row["CodeSigning"]


@pytest.mark.parametrize("response,detail,expected", [
    ({"FunctionName": NAME, "CodeSigningConfigArn": ""}, None, "FAIL"),
    ({"FunctionName": NAME, "CodeSigningConfigArn": CONFIG_ARN}, config(policy="Warn"), "FAIL"),
    ({"FunctionName": "foreign", "CodeSigningConfigArn": ""}, None, "UNKNOWN"),
])
def test_sdk_negative_and_malformed(monkeypatch, response, detail, expected):
    assert finding(monkeypatch, response, detail)[0] == expected


def test_sdk_denied_and_inactive(monkeypatch):
    assert finding(monkeypatch, None, error="AccessDeniedException")[0] == "UNKNOWN"
    assert finding(monkeypatch, {"FunctionName": NAME, "CodeSigningConfigArn": ""}, state="Inactive")[0] == "NOT_APPLICABLE"
