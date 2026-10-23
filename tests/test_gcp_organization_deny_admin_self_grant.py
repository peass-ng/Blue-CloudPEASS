"""Organization IAM write grants Deny Admin only when the access is new."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_gcp_organization_iam_self_grant import ORG, SOURCE, case


ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-organizations-setiampolicy-deny-admin")


def scenario():
    snap = case()
    snap["collections"][2]["items"].append({
        "name": "roles/iam.denyAdmin", "includedPermissions": ["iam.denypolicies.create"]})
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_org_writer_can_gain_deny_admin_permission():
    assert reached(scenario()) == [(
        "gcp_verified_authority:possible-org-deny-admin-self-grant:" + ORG, "conditional")]


def test_existing_permission_or_missing_writer_is_not_new_access():
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"].append({
        "role": "roles/iam.denyAdmin", "members": [SOURCE]})
    assert reached(snap) == []
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_missing_role_or_member_restriction_is_not_definite():
    snap = scenario()
    snap["collections"][2]["items"].pop()
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][2]["items"].pop()
    snap["collections"].append({"type": "iam_role_builtin", "scope": "projects/unrelated",
        "status": "collected", "items": [{"name": "roles/iam.denyAdmin",
        "includedPermissions": ["iam.denypolicies.create"]}]})
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][5]["items"].append({
        "name": ORG + "/policies/iam.allowedPolicyMemberDomains",
        "constraint": "iam.allowedPolicyMemberDomains",
        "spec": {"rules": [{"values": {"allowedValues": ["is:example.com"]}}]}})
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
