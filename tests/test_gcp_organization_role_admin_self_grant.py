"""Organization IAM write grants custom-role administration only when new."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_gcp_organization_iam_self_grant import ORG, SOURCE, case


ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-organizations-setiampolicy-role-admin")


def scenario():
    snap = case()
    snap["collections"][2]["items"].append({
        "name": "roles/iam.organizationRoleAdmin", "includedPermissions": ["iam.roles.create"]})
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_org_writer_can_gain_custom_role_administration():
    assert reached(scenario()) == [(
        "gcp_verified_authority:possible-org-role-admin-self-grant:" + ORG, "conditional")]


def test_existing_role_create_access_or_missing_writer_is_not_new_access():
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"].append({
        "role": "roles/iam.organizationRoleAdmin", "members": [SOURCE]})
    assert reached(snap) == []
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_missing_role_or_pab_binding_is_not_definite():
    snap = scenario()
    snap["collections"][2]["items"].pop()
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][6]["items"].append({
        "name": ORG + "/locations/global/policyBindings/limited",
        "policyKind": "PRINCIPAL_ACCESS_BOUNDARY"})
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
