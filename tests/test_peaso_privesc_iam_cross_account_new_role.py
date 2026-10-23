"""A future role ARN may match cross-account PrincipalArn trust only with an exact path."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc import schema, versioned_catalog
from tests.test_peaso_privesc_schema_ext import ACCOUNT, allow, aws_snap, reached, user


OTHER = "222222222222"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/alice"
TARGET = f"arn:aws:iam::{OTHER}:role/privileged"
NEW = f"arn:aws:iam::{ACCOUNT}:role/OpsRoles/PeasoCrossAccount0"
ID = "aws-iam-createrole-satisfy-cross-account-trust"
ENTRY = {key: value for key, value in next(
    row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"] if row["id"] == ID).items()
    if key != "_file"}


def _case(*, create=NEW, put=NEW, trust_principal=None, trust_pattern=None,
          existing=False, source_scp="empty", target_status="collected"):
    actor = user("alice", allow("iam:CreateRole", create), allow("iam:PutRolePolicy", put))
    snap = aws_snap([actor])
    snap["collections"] = [row for row in snap["collections"] if row["type"] != "scp_policy"]
    snap["collections"].append({"type": "scp_policy", "scope": f"{ACCOUNT}/global",
                                "service": "organizations", "status": source_scp,
                                "items": [], "error": None})
    if existing:
        next(row for row in snap["collections"] if row["type"] == "iam_role")["items"].append({
            "Arn": NEW, "RoleName": "PeasoCrossAccount0", "Path": "/OpsRoles/",
            "AssumeRolePolicyDocument": {"Statement": []}, "RolePolicyList": [],
            "AttachedManagedPolicies": [], "InstanceProfileList": []})
    trust = {"Effect": "Allow", "Action": "sts:AssumeRole",
             "Principal": {"AWS": trust_principal or f"arn:aws:iam::{ACCOUNT}:root"},
             "Condition": {"ArnLike": {"aws:PrincipalArn": trust_pattern or
                                      f"arn:aws:iam::{ACCOUNT}:role/OpsRoles/*"}}}
    target = {"Arn": TARGET, "RoleName": "privileged", "Path": "/",
              "AssumeRolePolicyDocument": {"Statement": [trust]}, "RolePolicyList": [
                  {"PolicyName": "privileged", "PolicyDocument": {"Statement": [allow("iam:*", "*")]}}],
              "AttachedManagedPolicies": [], "InstanceProfileList": []}
    snap["collections"].append({"type": "iam_role", "scope": f"{OTHER}/global",
                                "service": "iam", "status": target_status,
                                "items": [target] if target_status == "collected" else [], "error": None})
    return snap


def _edges(snapshot, *, include_unknown=False):
    return reached(privesc.analyze(snapshot, entries=[copy.deepcopy(ENTRY)],
                                   include_unknown=include_unknown), SOURCE, ID)


def test_new_role_matches_collected_cross_account_path_trust():
    assert schema.validate_entry(ENTRY)[0] == []
    assert _edges(_case()) == {TARGET: "conditional"}
    assert _edges(_case(trust_pattern=NEW)) == {TARGET: "conditional"}
    assert _edges(_case(trust_pattern="arn:aws:iam::*:role/OpsRoles/*")) == {
        TARGET: "conditional"}


def test_wrong_role_grants_direct_role_principal_or_taken_name_do_not_bind():
    assert not _edges(_case(create=f"arn:aws:iam::{ACCOUNT}:role/Other/*"))
    assert not _edges(_case(put=f"arn:aws:iam::{ACCOUNT}:role/Other/*"))
    assert not _edges(_case(trust_principal=NEW))
    assert not _edges(_case(existing=True))


def test_same_role_name_in_target_account_does_not_block_source_account_creation():
    snap = _case()
    target_roles = next(row for row in snap["collections"] if row["type"] == "iam_role"
                        and row["scope"] == f"{OTHER}/global")
    target_roles["items"].append({
        "Arn": f"arn:aws:iam::{OTHER}:role/OpsRoles/PeasoCrossAccount0",
        "RoleName": "PeasoCrossAccount0", "Path": "/OpsRoles/",
        "AssumeRolePolicyDocument": {"Statement": []}, "RolePolicyList": [],
        "AttachedManagedPolicies": [], "InstanceProfileList": []})
    assert _edges(snap) == {TARGET: "conditional"}


def test_missing_account_inventory_or_scp_is_unresolved():
    assert not _edges(_case(target_status="denied"))
    assert not _edges(_case(source_scp="denied"))


def test_notprincipal_deny_needs_separate_trust_review():
    snap = _case()
    target = next(row for row in snap["collections"] if row["type"] == "iam_role"
                  and row["scope"].startswith(OTHER))["items"][0]
    target["AssumeRolePolicyDocument"]["Statement"].append({
        "Effect": "Deny", "Action": "sts:AssumeRole",
        "NotPrincipal": {"AWS": f"arn:aws:iam::{OTHER}:root"}})
    assert not _edges(snap)


def test_forced_boundary_does_not_prove_the_new_role_can_assume_target():
    snap = _case()
    actor = next(row for row in snap["collections"] if row["type"] == "iam_user")["items"][0]
    create = actor["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]
    create["Condition"] = {"StringEquals": {"iam:PermissionsBoundary":
                          "arn:aws:iam::aws:policy/ReadOnlyAccess"}}
    assert not _edges(snap)


def test_current_binding_uses_exact_new_role_join_while_prior_entry_stays_archived():
    prior, _ = versioned_catalog._verified_prior()
    assert prior[ID]["target"]["selector"].get("trust_allows_principal_of_source") is True
    current, state = versioned_catalog.lookup_entries([ID], versioned_catalog.current_binding())
    assert state == "exact_strict_privesc"
    assert current[ID]["preconditions"] == ["iam_new_role_cross_account_trust"]
