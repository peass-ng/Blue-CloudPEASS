"""Tenant IAM self-grants need an exact tenant and a new user-update permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
TENANT = PROJECT + "/tenants/customer1"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/tenantWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": [
            "identitytoolkit.tenants.setIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("identityplatform_tenant", [{"name": TENANT,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_existing_tenant_and_policy_writer_give_conditional_path():
    assert reached(case()) == [("gcp_verified_authority:possible-identityplatform-tenant-self-grant:" +
                                TENANT, "conditional")]


def test_existing_user_update_or_no_writer_is_not_new_access():
    snap = case()
    snap["collections"][-1]["items"][0]["iamPolicy"]["bindings"] = [
        {"role": "roles/identityplatform.admin", "members": [SOURCE]}]
    assert reached(snap) == []
    snap = case()
    snap["collections"][2]["items"][0]["bindings"].append(
        {"role": "roles/identityplatform.admin", "members": [SOURCE]})
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []


def test_wrong_condition_or_incomplete_tenant_policy_is_not_definite():
    snap = case()
    binding = snap["collections"][2]["items"][0]["bindings"][0]
    binding["condition"] = {"expression": 'resource.name == "' + TENANT + '"'}
    assert reached(snap)[0][1] == "conditional"
    binding["condition"] = {"expression": 'resource.name == "' +
                            TENANT.replace("customer1", "customer2") + '"'}
    assert reached(snap) == []
    for mutate in (
        lambda s: s["collections"][-1]["items"][0]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-1]["items"].append(
            deepcopy(s["collections"][-1]["items"][0])),
        lambda s: s["collections"][-1]["items"][0].update(
            {"name": TENANT.replace("demo-project1", "foreign-project")}),
    ):
        snap = case(); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))
