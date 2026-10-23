"""Schema v1.1 AWS extensions requested by the catalog ledger: Cognito / Roles Anywhere membership selectors, collected
SageMaker notebook and Redshift Serverless hosts, trust-based fallbacks (Image Builder, HyperPod), derived sandbox /
dbuser placeholders and managed-service application-plane admin entities."""
from __future__ import annotations

from peaso import privesc

from tests.test_peaso_privesc_schema_ext import (ACCOUNT, ALICE, allow, aws_snap, entry, errors_of, pol, reached, role,
                                                 user)

SCOPE = f"{ACCOUNT}/us-east-1"


def role_arn(name):
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def federated_role(name, provider="cognito-identity.amazonaws.com"):
    item = role(name, "unused.amazonaws.com")
    item["AssumeRolePolicyDocument"] = pol({"Effect": "Allow", "Principal": {"Federated": provider},
                                            "Action": "sts:AssumeRoleWithWebIdentity"})
    return item


def with_collections(snap, *collections):
    for t, s, i, *st in collections:
        snap["collections"].append({"type": t, "scope": s, "service": t, "status": st[0] if st else "collected",
                                    "items": i, "error": None})
        snap["scopes"] = sorted(set(snap["scopes"]) | {s})
    return snap


def members(got):
    return {k: v for k, v in got.items() if not k.startswith(("unresolved:", "unknown:"))}


def assert_unknown_only(got):
    assert got and not members(got) and set(got.values()) == {"unknown"}


# ---------------------------------------------------------------- Cognito / Roles Anywhere
def cognito_entry(selector_key, action):
    return entry("aws-t-" + selector_key, "aws", {"all_of": [{"action": action, "resource": "{target.attached_resource_arn}"}]},
                 {"kind": "aws_role", "scope": "same_account",
                  "selector": {selector_key: action, "trust_allows_federated": "cognito-identity.amazonaws.com"}})


def test_cognito_selectors_drop_without_user_pools_and_stay_unknown_otherwise():
    entries = [cognito_entry("cognito_user_pool_covered_by", "cognito-idp:AdminCreateUser"),
               cognito_entry("cognito_user_pool_group_role_covered_by", "cognito-idp:AdminAddUserToGroup")]
    users = [user("alice", allow("cognito-idp:*"))]
    roles = [federated_role("idpool-auth"), role("lambda-role", "lambda.amazonaws.com")]
    for e in entries:
        # Not collected: an unresolved placeholder, never the role itself.
        assert_unknown_only(reached(privesc.analyze(aws_snap(users, roles), entries=[e], include_unknown=True), ALICE, e["id"]))
        # A user pool exists but group RoleArns / identity-pool mappings are not collected: still unknown.
        snap = with_collections(aws_snap(users, roles), ("cognito_user_pool", SCOPE, [{"Id": "us-east-1_abc", "Name": "p"}]))
        assert_unknown_only(reached(privesc.analyze(snap, entries=[e], include_unknown=True), ALICE, e["id"]))
        # Collected and empty: no user pool, no edge.
        snap = with_collections(aws_snap(users, roles), ("cognito_user_pool", SCOPE, [], "empty"))
        assert reached(privesc.analyze(snap, entries=[e]), ALICE, e["id"]) == {}


def test_rolesanywhere_profile_selector_needs_trust_anchors():
    e = entry("aws-t-ra", "aws", {"all_of": [{"action": "rolesanywhere:UpdateProfile", "resource": "{target.rolesanywhere_profile_arn}"}]},
              {"kind": "aws_role", "scope": "same_account",
               "selector": {"trust_allows_service": "rolesanywhere.amazonaws.com", "rolesanywhere_profile_includes_target": True}})
    assert not [x for x in errors_of(e) if "placeholder" in x]
    users = [user("alice", allow("rolesanywhere:UpdateProfile")), user("bob")]
    roles = [role("ra-role", "rolesanywhere.amazonaws.com"), role("ec2-role", "ec2.amazonaws.com")]
    got = reached(privesc.analyze(aws_snap(users, roles), entries=[e], include_unknown=True), ALICE)
    assert_unknown_only(got)
    assert reached(privesc.analyze(aws_snap(users, roles), entries=[e]), f"arn:aws:iam::{ACCOUNT}:user/bob") == {}
    anchor = {"trustAnchorArn": f"arn:aws:rolesanywhere:us-east-1:{ACCOUNT}:trust-anchor/a1", "enabled": True}
    snap = with_collections(aws_snap(users, roles), ("rolesanywhere_trust_anchor", SCOPE, [anchor]))
    assert_unknown_only(reached(privesc.analyze(snap, entries=[e], include_unknown=True), ALICE))
    snap = with_collections(aws_snap(users, roles), ("rolesanywhere_trust_anchor", SCOPE, [], "empty"))
    assert reached(privesc.analyze(snap, entries=[e]), ALICE) == {}


# ---------------------------------------------------------------- via_resource_type hosts
NOTEBOOK = f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:notebook-instance/nb1"


def notebook_entry():
    return entry("aws-t-nb", "aws", {"all_of": [{"action": "sagemaker:CreatePresignedNotebookInstanceUrl", "resource": "{target.resource_arn}"}]},
                 {"kind": "aws_role", "scope": "same_account",
                  "selector": {"attached_to_service": "sagemaker", "via_resource_type": "sagemaker_notebook_instance"}})


def test_sagemaker_notebook_instance_is_a_collected_host():
    users = [user("alice", allow("sagemaker:CreatePresignedNotebookInstanceUrl", NOTEBOOK)),
             user("bob", allow("sagemaker:CreatePresignedNotebookInstanceUrl", NOTEBOOK.replace("nb1", "other")))]
    roles = [role("nb-role", "sagemaker.amazonaws.com"), role("idle-role", "sagemaker.amazonaws.com")]
    nb = {"NotebookInstanceName": "nb1", "NotebookInstanceArn": NOTEBOOK, "RoleArn": role_arn("nb-role")}
    snap = with_collections(aws_snap(users, roles), ("sagemaker_notebook_instance", SCOPE, [nb]))
    result = privesc.analyze(snap, entries=[notebook_entry()])
    # attached_to_service: sagemaker defers to the collected notebook host: derived, only for the notebook's role.
    assert reached(result, ALICE) == {role_arn("nb-role"): "derived"}
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/bob") == {}
    # Detail read failed (no RoleArn): partial inventory, the trust fallback keeps the roles unknown (bob is left out:
    # sources with identical placeholder reaches are grouped).
    users = users[:1]
    snap = with_collections(aws_snap(users, roles), ("sagemaker_notebook_instance", SCOPE, [{"NotebookInstanceName": "nb1",
                                                                                             "NotebookInstanceArn": NOTEBOOK}]))
    assert_unknown_only(reached(privesc.analyze(snap, entries=[notebook_entry()], include_unknown=True), ALICE))
    # Not collected at all: trust-based fallback, unknown.
    assert_unknown_only(reached(privesc.analyze(aws_snap(users, roles), entries=[notebook_entry()], include_unknown=True), ALICE))


def test_redshift_serverless_workgroup_carries_namespace_roles():
    # A trust_allows_service list requires every service; this role trusts Redshift alone.
    wg = f"arn:aws:redshift-serverless:us-east-1:{ACCOUNT}:workgroup/w-1"
    e = entry("aws-t-rs", "aws", {"all_of": [{"action": "redshift-serverless:GetCredentials", "resource": "{target.resource_arn}"}]},
              {"kind": "aws_role", "scope": "same_account",
               "selector": {"trust_allows_service": "redshift.amazonaws.com",
                            "via_resource_type": "redshift_serverless_workgroup"}})
    users = [user("alice", allow("redshift-serverless:GetCredentials", wg))]
    roles = [role("ns-role", "redshift.amazonaws.com"), role("other-rs", "redshift-serverless.amazonaws.com")]
    namespace = {"namespaceName": "ns", "iamRoles": [f"IamRole(applyStatus=in-sync, iamRoleArn={role_arn('ns-role')})"]}
    workgroup = {"workgroupName": "wg", "workgroupArn": wg, "namespaceName": "ns"}
    snap = with_collections(aws_snap(users, roles), ("redshiftserverless_namespace", SCOPE, [namespace]),
                            ("redshiftserverless_workgroup", SCOPE, [workgroup]))
    assert reached(privesc.analyze(snap, entries=[e]), ALICE) == {role_arn("ns-role"): "derived"}
    # Workgroup without its namespace listed: partial, unknown.
    snap = with_collections(aws_snap(users, roles), ("redshiftserverless_workgroup", SCOPE, [workgroup]))
    assert_unknown_only(reached(privesc.analyze(snap, entries=[e], include_unknown=True), ALICE))


def test_uncollected_resource_types_use_the_trust_fallback():
    users = [user("alice", allow("imagebuilder:*"), allow("sagemaker:*"), allow("iam:PassRole"))]
    roles = [role("build", "ec2.amazonaws.com"), role("fn", "lambda.amazonaws.com"), role("hp", "sagemaker.amazonaws.com")]
    ib = entry("aws-t-ib", "aws", {"all_of": [{"action": "imagebuilder:StartImagePipelineExecution", "resource": "{target.attached_resource_arn}"}]},
               {"kind": "aws_role", "scope": "same_account", "selector": {"via_resource_type": "imagebuilder_pipeline"}})
    hp = entry("aws-t-hp", "aws", {"all_of": [{"action": "sagemaker:UpdateClusterSoftware", "resource": "{target.resource_arn}"}]},
               {"kind": "aws_role", "scope": "same_account",
                "selector": {"attached_to_service": "sagemaker", "via_resource_type": "sagemaker_cluster"}})
    result = privesc.analyze(aws_snap(users, roles), entries=[ib, hp], include_unknown=True)
    for technique in ("aws-t-ib", "aws-t-hp"):
        assert_unknown_only(reached(result, ALICE, technique))
    # Image Builder builds run as the EC2 instance-profile role: a lambda-only role is not a candidate.
    no_ec2 = privesc.analyze(aws_snap(users, [role("fn", "lambda.amazonaws.com")]), entries=[ib])
    assert reached(no_ec2, ALICE, "aws-t-ib") == {}


# ---------------------------------------------------------------- derived placeholders
def test_codebuild_sandbox_and_redshift_dbuser_placeholders():
    project = f"arn:aws:codebuild:us-east-1:{ACCOUNT}:project/proj"
    sandbox = f"arn:aws:codebuild:us-east-1:{ACCOUNT}:sandbox/proj:*"
    cb = entry("aws-t-cb", "aws", {"all_of": [{"action": "codebuild:StartCommandExecution", "resource": "{target.codebuild_sandbox_arn}"}]},
               {"kind": "aws_role", "scope": "same_account", "selector": {"attached_to_service": "codebuild"}})
    rs = entry("aws-t-dbuser", "aws", {"all_of": [{"action": "redshift:GetClusterCredentials", "resource": "{target.redshift_dbuser_arn}"}]},
               {"kind": "aws_role", "scope": "same_account",
                "selector": {"trust_allows_service": "redshift.amazonaws.com", "via_resource_type": "redshift_cluster"}})
    for e in (cb, rs):
        assert not [x for x in errors_of(e) if "placeholder" in x]
    users = [user("alice", allow("codebuild:StartCommandExecution", sandbox),
                  allow("redshift:GetClusterCredentials", f"arn:aws:redshift:*:{ACCOUNT}:dbuser:c1/*")),
             user("bob", allow("codebuild:StartCommandExecution", project),
                  allow("redshift:GetClusterCredentials", f"arn:aws:redshift:*:{ACCOUNT}:dbuser:other/*"))]
    roles = [role("cb-role", "codebuild.amazonaws.com"), role("rs-role", "redshift.amazonaws.com")]
    projects = {"Configuration": {"projects": [{"arn": project, "serviceRole": role_arn("cb-role")}]}}
    cluster = {"ClusterIdentifier": "c1", "IamRoles": [{"IamRoleArn": role_arn("rs-role")}]}
    snap = with_collections(aws_snap(users, roles), ("codebuild_project", SCOPE, [projects]), ("redshift_cluster", SCOPE, [cluster]))
    result = privesc.analyze(snap, entries=[cb, rs])
    assert reached(result, ALICE, "aws-t-cb") == {role_arn("cb-role"): "derived"}
    assert reached(result, ALICE, "aws-t-dbuser") == {role_arn("rs-role"): "derived"}
    bob = f"arn:aws:iam::{ACCOUNT}:user/bob"
    assert reached(result, bob, "aws-t-cb") == {} and reached(result, bob, "aws-t-dbuser") == {}


# ---------------------------------------------------------------- managed-service application plane
def plane_entry(selector):
    return entry("aws-t-plane", "aws", {"all_of": [{"action": "connect:GetFederationToken", "resource": "{target.scope}"}]},
                 {"kind": "aws_service_plane_admin", "scope": "same_account", "selector": selector})


def test_service_plane_admin_is_an_unknown_placeholder_for_holders():
    e = plane_entry({"service_plane": "connect"})
    assert not errors_of(e)
    snap = aws_snap([user("alice", allow("connect:GetFederationToken")), user("bob")])
    result = privesc.analyze(snap, entries=[e], include_unknown=True)
    assert_unknown_only(reached(result, ALICE, "aws-t-plane"))
    assert reached(result, f"arn:aws:iam::{ACCOUNT}:user/bob", "aws-t-plane") == {}


def test_service_plane_validation():
    assert any("service_plane" in x for x in errors_of(plane_entry({})))
    assert any("service_plane" in x for x in errors_of(plane_entry({"service_plane": "not-a-plane"})))
    wrong_kind = entry("aws-t-wrong", "aws", {"all_of": [{"action": "connect:GetFederationToken", "resource": "*"}]},
                       {"kind": "aws_role", "scope": "same_account", "selector": {"service_plane": "connect"}})
    assert any("service_plane" in x for x in errors_of(wrong_kind))
