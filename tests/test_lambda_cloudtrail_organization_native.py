"""Collector-to-engine regression for member-visible CloudTrail organization trails.

Move this file to tests/ with the guarded source patch. No live AWS calls occur.
"""
from __future__ import annotations

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.checks import claude_aws_b  # noqa: F401 - register the real callback

ACCOUNT = "123456789012"
OWNER = "999999999999"
REGION = "us-east-1"
FUNCTION_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:review"
CID = "aws.cb.lambda.cloudtrail_data_events"


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id="fixture-key",
                            aws_secret_access_key="fixture-secret",
                            region_name=REGION)
    clients, stubs = {}, {}

    def add(service, region=REGION):
        key = (service, region)
        if key not in clients:
            clients[key] = session.client(service, region_name=region)
            stubs[key] = Stubber(clients[key])
            stubs[key].activate()
        return stubs[key]

    monkeypatch.setattr(aws.Requests, "client",
                        lambda self, _session, service, region: clients[(service, region)])
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    yield add
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()


def _finding(sdk, mode):
    home = "eu-west-1" if mode == "shadow_only" else REGION
    owner = ACCOUNT if mode == "same_account" else OWNER
    org = mode != "foreign_non_org"
    trail_arn = f"arn:aws:cloudtrail:{home}:{owner}:trail/review"
    trail = {"Name": "review", "TrailARN": trail_arn, "HomeRegion": home,
             "IsMultiRegionTrail": True, "IsOrganizationTrail": org}
    sts = sdk("sts")
    sts.add_response("get_caller_identity",
                     {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer",
                      "UserId": "AIDAREVIEWER"}, {})
    sdk("ec2").add_response("describe_regions",
                            {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]},
                            {"AllRegions": True})

    cloudtrail = sdk("cloudtrail", REGION)
    cloudtrail.add_response("describe_trails", {"trailList": [trail]},
                            {"includeShadowTrails": True})
    details = sdk("cloudtrail", home)
    details.add_response("get_trail_status", {"IsLogging": True}, {"Name": trail_arn})
    if mode == "selector_denied":
        details.add_client_error("get_event_selectors", "AccessDeniedException",
                                 expected_params={"TrailName": trail_arn})
    else:
        fields = [{"Field": "eventCategory",
                   "Equals": ["Management" if mode == "management" else "Data"]}]
        if mode != "management":
            fields.append({"Field": "resources.type", "Equals": ["AWS::Lambda::Function"]})
        details.add_response("get_event_selectors",
                             {"TrailARN": trail_arn,
                              "AdvancedEventSelectors": [{"Name": "review", "FieldSelectors": fields}]},
                             {"TrailName": trail_arn})
    details.add_client_error("get_insight_selectors", "InsightNotEnabledException",
                             expected_params={"TrailName": trail_arn})

    lam = sdk("lambda")
    lam.add_response("list_functions",
                     {"Functions": [{"FunctionName": "review", "FunctionArn": FUNCTION_ARN,
                                     "PackageType": "Zip"}]}, {})
    lam.add_client_error("get_policy", "ResourceNotFoundException",
                         expected_params={"FunctionName": "review"})
    lam.add_client_error("get_function_url_config", "ResourceNotFoundException",
                         expected_params={"FunctionName": "review"})
    lam.add_response("get_function_concurrency", {}, {"FunctionName": "review"})
    lam.add_response("get_function_configuration",
                     {"FunctionName": "review", "FunctionArn": FUNCTION_ARN,
                      "PackageType": "Zip"}, {"FunctionName": "review"})
    lam.add_response("get_function_code_signing_config",
                     {"FunctionName": "review", "CodeSigningConfigArn": ""},
                     {"FunctionName": "review"})
    lam.add_response("get_runtime_management_config", {"UpdateRuntimeOn": "Auto"},
                     {"FunctionName": "review"})

    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT],
                            "options": {"service_concurrency": 1, "scope_concurrency": 1}},
                           ["lambda_function", "cloudtrail", "cloudtrail_account_inventory"])
    findings = [row for row in evaluate_snapshot(snapshot, checks=[CID],
                                                  include_not_applicable=True)["findings"]
                if row["check_id"] == CID and row["scope"] == f"{ACCOUNT}/{REGION}"]
    assert len(findings) == 1
    return snapshot, findings[0]


@pytest.mark.parametrize("mode,expected", [
    ("data", "PASS"),
    ("management", "FAIL"),
    ("foreign_non_org", "UNKNOWN"),
    ("selector_denied", "UNKNOWN"),
    ("shadow_only", "UNKNOWN"),
])
def test_organization_trail_native_collector_to_engine(sdk, mode, expected):
    snapshot, finding = _finding(sdk, mode)
    assert finding["status"] == expected
    global_trails = next(c for c in snapshot["collections"]
                         if c["type"] == "cloudtrail_account_inventory")
    assert global_trails["status"] == ("partial" if mode in
                                      {"foreign_non_org", "shadow_only"} else "collected")
    if mode in {"data", "management"}:
        row = global_trails["items"][0]
        assert row["_account_trail_binding"]["caller_account_id"] == ACCOUNT
        assert row["_account_trail_binding"]["include_shadow_trails"] is True
        assert row["SourceRegion"] == row["HomeRegion"] == REGION
