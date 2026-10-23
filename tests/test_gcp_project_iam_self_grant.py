"""Project policy write reaches Editor only when it adds real project access."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
SOURCE = "user:operator@example.com"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-projects-setiampolicy")


def envelope(kind, rows):
    return {"type": kind, "scope": PROJECT,
            "status": "collected" if rows else "empty", "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": "projects/123456789", "projectId": "demo-project1",
                              "state": "ACTIVE"}]),
        envelope("iam_policy", [{"name": PROJECT, "_representation": "full", "bindings": [
            {"role": "roles/resourcemanager.projectIamAdmin", "members": [SOURCE]}]}]),
        envelope("iam_role_builtin", [{"name": "roles/editor", "includedPermissions": [
            "compute.instances.create", "serviceusage.services.enable"]}]),
        envelope("iam_role", []), envelope("iam_deny_policy", []),
        envelope("org_policy_effective", []), envelope("policy_binding", []),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_new_editor_permission_is_a_conditional_project_self_grant():
    assert reached(case()) == [(
        "gcp_verified_authority:possible-project-editor-self-grant:" + PROJECT, "conditional")]


def test_existing_editor_or_missing_policy_writer_is_not_new_access():
    snap = case()
    snap["collections"][1]["items"][0]["bindings"].append(
        {"role": "roles/editor", "members": [SOURCE]})
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_other_new_editor_permission_still_reaches_project():
    snap = case()
    snap["collections"][1]["items"][0]["bindings"].append({
        "role": "projects/demo-project1/roles/computeCreator", "members": [SOURCE]})
    snap["collections"][3]["items"].append({
        "name": "projects/demo-project1/roles/computeCreator",
        "includedPermissions": ["compute.instances.create"]})
    assert reached(snap) == [(
        "gcp_verified_authority:possible-project-editor-self-grant:" + PROJECT, "conditional")]


def test_project_below_a_folder_does_not_need_folder_custom_role_inventory():
    folder, organization = "folders/123456", "organizations/654321"
    snap = case()
    snap["collections"][0]["items"][0]["parent"] = folder
    snap["collections"].extend([
        {"type": "folder", "scope": folder, "status": "collected", "items": [
            {"name": folder, "parent": organization, "state": "ACTIVE"}]},
        {"type": "organization", "scope": organization, "status": "collected", "items": [
            {"name": organization, "state": "ACTIVE"}]},
    ])
    for scope in (folder, organization):
        snap["collections"].extend([
            {"type": "iam_policy", "scope": scope, "status": "collected", "items": [
                {"name": scope, "_representation": "full", "bindings": []}]},
            {"type": "iam_deny_policy", "scope": scope, "status": "empty", "items": []},
            {"type": "policy_binding", "scope": scope, "status": "empty", "items": []},
        ])
    snap["collections"].extend([
        {"type": "iam_role", "scope": organization, "status": "empty", "items": []},
        {"type": "principal_access_boundary_policy", "scope": organization,
         "status": "empty", "items": []},
    ])
    assert reached(snap) == [(
        "gcp_verified_authority:possible-project-editor-self-grant:" + PROJECT, "conditional")]


def test_incomplete_or_restrictive_inputs_never_make_a_definite_path():
    for change in (
        lambda s: s["collections"][0]["items"][0].update({"state": "DELETE_REQUESTED"}),
        lambda s: s["collections"][0]["items"].append(deepcopy(s["collections"][0]["items"][0])),
        lambda s: s["collections"][1]["items"][0].pop("_representation"),
        lambda s: s["collections"][1]["items"][0]["bindings"].append({
            "role": "roles/editor", "members": ["group:admins@example.com"]}),
        lambda s: s["collections"][4].update({"status": "denied"}),
        lambda s: s["collections"][1]["items"][0]["bindings"][0].update({
            "condition": {"expression": "request.time < timestamp('2020-01-01T00:00:00Z')"}}),
        lambda s: s["collections"][5]["items"].append({
            "name": PROJECT + "/policies/iam.allowedPolicyMemberDomains",
            "constraint": "iam.allowedPolicyMemberDomains",
            "spec": {"rules": [{"values": {"allowedValues": ["is:example.com"]}}]}}),
        lambda s: s["collections"][6]["items"].append({
            "name": PROJECT + "/locations/global/policyBindings/limited",
            "policyKind": "PRINCIPAL_ACCESS_BOUNDARY"}),
    ):
        snap = case(); change(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_default_service_account_editor_block_is_respected():
    account = "serviceAccount:demo-project1@appspot.gserviceaccount.com"
    snap = case()
    snap["collections"][1]["items"][0]["bindings"][0]["members"] = [account]
    snap["collections"][5]["items"].append({
        "name": PROJECT + "/policies/iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts",
        "constraint": "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts",
        "spec": {"rules": [{"enforce": True}]}})
    edges = Evaluator(GcpModel(snap), [ENTRY], include_unknown=True, admin_scopes={}).run()
    assert not any(edge.source.id == account and grant.confidence == "conditional"
                   for edge in edges for grant in edge.targets.values())
    snap["collections"][5]["items"][0]["spec"]["rules"][0]["enforce"] = False
    edges = Evaluator(GcpModel(snap), [ENTRY], include_unknown=True, admin_scopes={}).run()
    assert any(edge.source.id == account and grant.confidence == "conditional"
               for edge in edges for grant in edge.targets.values())
