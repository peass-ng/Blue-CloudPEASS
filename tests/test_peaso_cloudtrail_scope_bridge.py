"""Offline account inventory, native IAM permission, and signed scope join."""
import json
import pytest

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.collectors.aws_cloudtrail_delivery_native import ACTIONS

CHECK = "aws_nist_cloudtrail_trail_integrated_with_logs"
TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/main"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/cloudtrail"
GROUP = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:trail"
STREAM = f"{GROUP}:log-stream:{ACCOUNT}_CloudTrail_{REGION}"


@pytest.mark.parametrize("policy_scope,expected", [("broad", "PASS"), ("base", "UNKNOWN"), ("denied", "FAIL"), ("unselected", "UNKNOWN")])
def test_account_inventory_joins_strict_permission_to_signed_scope(sdk, monkeypatch, policy_scope, expected):
    decision = "implicitDeny" if policy_scope == "denied" else "allowed"
    session, add = sdk
    sts, ec2, ct, iam, logs = (add(name) for name in ("sts", "ec2", "cloudtrail", "iam", "logs"))
    sts.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "reviewer"}, {})
    ec2.add_response("describe_regions", {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    trail = {"Name": "main", "TrailARN": TRAIL, "HomeRegion": REGION, "S3BucketName": "bucket",
             "IsOrganizationTrail": False, "IsMultiRegionTrail": False,
             "CloudWatchLogsRoleArn": ROLE, "CloudWatchLogsLogGroupArn": GROUP}
    ct.add_response("describe_trails", {"trailList": [trail]}, {"includeShadowTrails": True})
    ct.add_response("get_trail_status", {"IsLogging": True}, {"Name": TRAIL})
    ct.add_response("get_event_selectors", {"TrailARN": TRAIL, "EventSelectors": []}, {"TrailName": TRAIL})
    ct.add_client_error("get_insight_selectors", "InsightNotEnabledException", expected_params={"TrailName": TRAIL})
    if policy_scope != "unselected":
        ct.add_response("describe_trails", {"trailList": [trail]}, {"includeShadowTrails": False})
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}, "ArnEquals": {"aws:SourceArn": TRAIL}}}]}
        iam.add_response("get_role", {"Role": {"Path": "/", "RoleName": "cloudtrail", "RoleId": "AROA12345678901234567",
                         "Arn": ROLE, "CreateDate": __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
                         "AssumeRolePolicyDocument": json.dumps(trust)}}, {"RoleName": "cloudtrail"})
        iam.add_response("get_context_keys_for_principal_policy", {"ContextKeyNames": []}, {"PolicySourceArn": ROLE})
        results = [{"EvalActionName": action, "EvalResourceName": STREAM,
                    "EvalDecision": "allowed" if action == ACTIONS[0] else decision, "MissingContextValues": []} for action in ACTIONS]
        iam.add_response("simulate_principal_policy", {"EvaluationResults": results, "IsTruncated": False},
                         {"PolicySourceArn": ROLE, "ActionNames": ACTIONS, "ResourceArns": [STREAM]})
        if policy_scope != "denied":
            iam.add_response("list_role_policies", {"PolicyNames": ["delivery"], "IsTruncated": False}, {"RoleName": "cloudtrail"})
            iam.add_response("list_attached_role_policies", {"AttachedPolicies": [], "IsTruncated": False}, {"RoleName": "cloudtrail"})
            policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ACTIONS,
                      "Resource": STREAM + ("*" if policy_scope == "broad" else "")}]}
            iam.add_response("get_role_policy", {"RoleName": "cloudtrail", "PolicyName": "delivery", "PolicyDocument": json.dumps(policy)},
                             {"RoleName": "cloudtrail", "PolicyName": "delivery"})
    logs.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "trail", "arn": GROUP + ":*"}]}, {})
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {"service_concurrency": 1, "retry_attempts": 1}},
                           ["cloudtrail_account_inventory", "log_group"] +
                           ([] if policy_scope == "unselected" else ["cloudtrail_delivery_role_scope"]))
    finding = evaluate_snapshot(snapshot, checks=[CHECK])["findings"][0]
    assert finding["status"] == expected, finding
    account = next(row for row in snapshot["collections"] if row["type"] == "cloudtrail_account_inventory")
    if policy_scope == "unselected":
        assert "CloudWatchLogsRole" not in account["items"][0]
    else:
        joined = account["items"][0]["CloudWatchLogsRole"]
        assert joined["_provenance"]["simulated_resource_arn"] == STREAM
    assert account["items"][0]["_coverage"]["S3KeyPrefix"]["status"] == "empty"
    for name, stub in (("sts", sts), ("ec2", ec2), ("cloudtrail", ct), ("iam", iam), ("logs", logs)):
        assert not stub._queue, (name, len(stub._queue))
