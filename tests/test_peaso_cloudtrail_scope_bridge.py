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


@pytest.mark.parametrize("policy_scope,expected", [("broad", "PASS"), ("base", "UNKNOWN"), ("denied", "FAIL"), ("unselected", "UNKNOWN"),
                                                     ("broad_multi", "PASS"), ("home_multi", "UNKNOWN"), ("denied_multi", "FAIL"),
                                                     ("attached_multi", "PASS"), ("policy_deny_multi", "UNKNOWN"),
                                                     ("boundary_broad_multi", "PASS"), ("boundary_home_multi", "UNKNOWN"),
                                                     ("org_multi", "UNKNOWN")])
def test_account_inventory_joins_strict_permission_to_signed_scope(sdk, monkeypatch, policy_scope, expected):
    decision = "implicitDeny" if policy_scope.startswith("denied") else "allowed"
    multi = policy_scope.endswith("_multi")
    organization = policy_scope == "org_multi"
    session, add = sdk
    sts, ec2, ct, iam, logs = (add(name) for name in ("sts", "ec2", "cloudtrail", "iam", "logs"))
    sts.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/reviewer", "UserId": "reviewer"}, {})
    ec2.add_response("describe_regions", {"Regions": [{"RegionName": REGION, "OptInStatus": "opt-in-not-required"}]}, {"AllRegions": True})
    trail = {"Name": "main", "TrailARN": TRAIL, "HomeRegion": REGION, "S3BucketName": "bucket",
             "IsOrganizationTrail": organization, "IsMultiRegionTrail": multi,
             "CloudWatchLogsRoleArn": ROLE, "CloudWatchLogsLogGroupArn": GROUP}
    ct.add_response("describe_trails", {"trailList": [trail]}, {"includeShadowTrails": True})
    ct.add_response("get_trail_status", {"IsLogging": True}, {"Name": TRAIL})
    ct.add_response("get_event_selectors", {"TrailARN": TRAIL, "EventSelectors": []}, {"TrailName": TRAIL})
    ct.add_client_error("get_insight_selectors", "InsightNotEnabledException", expected_params={"TrailName": TRAIL})
    if policy_scope != "unselected" and not organization:
        ct.add_response("describe_trails", {"trailList": [trail]}, {"includeShadowTrails": False})
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
                 "Principal": {"Service": "cloudtrail.amazonaws.com"},
                 "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}, "ArnEquals": {"aws:SourceArn": TRAIL}}}]}
        role = {"Path": "/", "RoleName": "cloudtrail", "RoleId": "AROA12345678901234567",
                         "Arn": ROLE, "CreateDate": __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc),
                         "AssumeRolePolicyDocument": json.dumps(trust)}
        boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/boundary"
        if policy_scope.startswith("boundary"):
            role["PermissionsBoundary"] = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": boundary_arn}
        iam.add_response("get_role", {"Role": role}, {"RoleName": "cloudtrail"})
        iam.add_response("get_context_keys_for_principal_policy", {"ContextKeyNames": []}, {"PolicySourceArn": ROLE})
        results = [{"EvalActionName": action, "EvalResourceName": STREAM,
                    "EvalDecision": "allowed" if action == ACTIONS[0] else decision, "MissingContextValues": []} for action in ACTIONS]
        if policy_scope.startswith("boundary"):
            for result in results:
                result["PermissionsBoundaryDecisionDetail"] = {"AllowedByPermissionsBoundary": True}
        iam.add_response("simulate_principal_policy", {"EvaluationResults": results, "IsTruncated": False},
                         {"PolicySourceArn": ROLE, "ActionNames": ACTIONS, "ResourceArns": [STREAM]})
        if not policy_scope.startswith("denied"):
            attached_arn = f"arn:aws:iam::{ACCOUNT}:policy/delivery"
            iam.add_response("list_role_policies", {"PolicyNames": [] if policy_scope == "attached_multi" else ["delivery"], "IsTruncated": False}, {"RoleName": "cloudtrail"})
            iam.add_response("list_attached_role_policies", {"AttachedPolicies": [{"PolicyName": "delivery", "PolicyArn": attached_arn}] if policy_scope == "attached_multi" else [], "IsTruncated": False}, {"RoleName": "cloudtrail"})
            all_regions = f"{GROUP}:log-stream:{ACCOUNT}_CloudTrail_*"
            resource = (all_regions if multi and policy_scope in {"broad_multi", "attached_multi", "policy_deny_multi", "boundary_broad_multi", "boundary_home_multi"}
                        else STREAM + ("*" if policy_scope in {"broad", "home_multi"} else ""))
            statements = [{"Effect": "Allow", "Action": ACTIONS, "Resource": resource}]
            if policy_scope == "policy_deny_multi":
                statements.append({"Effect": "Deny", "Action": "logs:PutLogEvents", "Resource": "*"})
            policy = {"Version": "2012-10-17", "Statement": statements}
            if policy_scope == "attached_multi":
                iam.add_response("get_policy", {"Policy": {"Arn": attached_arn, "PolicyName": "delivery", "DefaultVersionId": "v1"}}, {"PolicyArn": attached_arn})
                iam.add_response("get_policy_version", {"PolicyVersion": {"VersionId": "v1", "IsDefaultVersion": True, "Document": json.dumps(policy)}},
                                 {"PolicyArn": attached_arn, "VersionId": "v1"})
            else:
                iam.add_response("get_role_policy", {"RoleName": "cloudtrail", "PolicyName": "delivery", "PolicyDocument": json.dumps(policy)},
                                 {"RoleName": "cloudtrail", "PolicyName": "delivery"})
            if policy_scope.startswith("boundary"):
                iam.add_response("get_policy", {"Policy": {"Arn": boundary_arn, "PolicyName": "boundary", "DefaultVersionId": "v1"}}, {"PolicyArn": boundary_arn})
                boundary_resource = STREAM + "*" if policy_scope == "boundary_home_multi" else all_regions
                boundary_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ACTIONS, "Resource": boundary_resource}]}
                iam.add_response("get_policy_version", {"PolicyVersion": {"VersionId": "v1", "IsDefaultVersion": True, "Document": json.dumps(boundary_doc)}},
                                 {"PolicyArn": boundary_arn, "VersionId": "v1"})
    logs.add_response("describe_log_groups", {"logGroups": [{"logGroupName": "trail", "arn": GROUP + ":*"}]}, {})
    monkeypatch.setattr(aws, "_session", lambda auth, region: (session, "fixture"))
    snapshot = aws.collect({"provider": "aws", "scopes": [ACCOUNT], "options": {"service_concurrency": 1, "retry_attempts": 1}},
                           ["cloudtrail_account_inventory", "log_group"] +
                           ([] if policy_scope == "unselected" else ["cloudtrail_delivery_role_scope"]))
    finding = evaluate_snapshot(snapshot, checks=[CHECK])["findings"][0]
    assert finding["status"] == expected, finding
    account = next(row for row in snapshot["collections"] if row["type"] == "cloudtrail_account_inventory")
    if policy_scope in {"unselected", "org_multi"}:
        assert "CloudWatchLogsRole" not in account["items"][0]
    else:
        joined = account["items"][0]["CloudWatchLogsRole"]
        assert joined["_provenance"]["simulated_resource_arn"] == STREAM
        if multi:
            if policy_scope not in {"denied_multi", "policy_deny_multi"}:
                assert joined["supported_stream_prefix"] == f"{GROUP}:log-stream:{ACCOUNT}_CloudTrail_*"
            if expected == "PASS":
                assert joined["full_role_stream_scope_proven"] is True
                assert joined["_provenance"]["role_scope_proof"]["stream_region_scope"] == "all_source_regions"
    assert account["items"][0]["_coverage"]["S3KeyPrefix"]["status"] == "empty"
    for name, stub in (("sts", sts), ("ec2", ec2), ("cloudtrail", ct), ("iam", iam), ("logs", logs)):
        assert not stub._queue, (name, len(stub._queue))
