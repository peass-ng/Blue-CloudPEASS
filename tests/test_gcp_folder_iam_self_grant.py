"""Folder policy writes must add an actual Folder Admin permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


FOLDER = "folders/123456"
ORG = "organizations/654321"
PROJECT = "projects/demo-project1"
SOURCE = "user:operator@example.com"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-folders-setiampolicy")


def envelope(kind, scope, rows):
    return {"type": kind, "scope": scope,
            "status": "collected" if rows else "empty", "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("organization", ORG, [{"name": ORG}]),
        envelope("folder", FOLDER, [{"name": FOLDER, "parent": ORG, "state": "ACTIVE"}]),
        envelope("iam_policy", ORG, [{"name": ORG, "bindings": [], "_representation": "full"}]),
        envelope("iam_policy", FOLDER, [{"name": FOLDER, "_representation": "full",
            "bindings": [{"role": "roles/resourcemanager.folderIamAdmin", "members": [SOURCE]}]}]),
        envelope("iam_role", ORG, []),
        envelope("iam_role_builtin", PROJECT, [{"name": "roles/resourcemanager.folderAdmin",
            "includedPermissions": ["resourcemanager.folders.setIamPolicy",
                                    "resourcemanager.folders.create",
                                    "resourcemanager.folders.delete",
                                    "resourcemanager.folders.move",
                                    "resourcemanager.folders.update",
                                    "resourcemanager.folders.undelete",
                                    "resourcemanager.projects.setIamPolicy"]}]),
        envelope("iam_deny_policy", ORG, []),
        envelope("iam_deny_policy", FOLDER, []),
        envelope("folder_policy_grant_constraints", FOLDER, []),
        envelope("policy_binding", ORG, []),
        envelope("policy_binding", FOLDER, []),
        envelope("principal_access_boundary_policy", ORG, []),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_active_folder_with_new_admin_permission_is_conditional():
    assert reached(case()) == [(
        "gcp_verified_authority:possible-folder-self-grant:" + FOLDER, "conditional")]


def test_existing_folder_admin_and_absent_writer_are_not_escalations():
    snap = case()
    snap["collections"][3]["items"][0]["bindings"][0]["role"] = "roles/resourcemanager.folderAdmin"
    assert reached(snap) == []
    snap = case()
    snap["collections"][3]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_incomplete_policy_or_restrictive_org_policy_is_not_definite():
    for change in (
        lambda s: s["collections"][3]["items"][0].pop("_representation"),
        lambda s: s["collections"][8]["items"].append(
            {"name": FOLDER + "/policies/iam.allowedPolicyMemberDomains",
             "constraint": "iam.allowedPolicyMemberDomains"}),
        lambda s: s["collections"][1]["items"][0].update({"state": "DELETE_REQUESTED"}),
        lambda s: s["collections"][3]["items"].append(deepcopy(s["collections"][3]["items"][0])),
        lambda s: s["collections"][9]["items"].append({
            "name": ORG + "/locations/global/policyBindings/limited",
            "policyKind": "PRINCIPAL_ACCESS_BOUNDARY"}),
    ):
        snap = case(); change(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_descendant_project_iam_gain_is_kept_when_folder_actions_exist():
    snap = case()
    folder_permissions = snap["collections"][5]["items"][0]["includedPermissions"][:-1]
    role = ORG + "/roles/folderActionsWithoutProjectIam"
    snap["collections"][4] = envelope("iam_role", ORG, [
        {"name": role, "includedPermissions": folder_permissions}])
    snap["collections"][3]["items"][0]["bindings"][0]["role"] = role
    snap["collections"].extend([
        envelope("project", PROJECT, [{"name": "projects/987654321", "projectId": "demo-project1",
                                       "parent": FOLDER}]),
        envelope("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [],
                                           "_representation": "full"}]),
        envelope("iam_role", PROJECT, []),
        envelope("iam_deny_policy", PROJECT, []),
        envelope("policy_binding", PROJECT, []),
    ])
    assert reached(snap) == [(
        "gcp_verified_authority:possible-folder-self-grant:" + FOLDER, "conditional")]


def test_folder_role_and_member_constraints_use_read_only_endpoints(monkeypatch):
    import sys
    import types
    from pathlib import Path

    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url))
            if url.endswith("/roles/resourcemanager.folderAdmin"):
                return {"name": "roles/resourcemanager.folderAdmin",
                        "includedPermissions": ["resourcemanager.folders.update"]}, "role"
            return {"name": url.removeprefix("https://orgpolicy.googleapis.com/v2/")
                    .removesuffix(":getEffectivePolicy"),
                    "spec": {"rules": [{"allowAll": True}]}}, "effective-policy"

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [FOLDER], "options": {
        "inventories": ["iam_role_builtin", "folder_policy_grant_constraints"],
        "include_inherited": False, "concurrency": 1}}, transport=transport)
    for kind, scope, service, fetch in collector.scope_jobs(FOLDER):
        if kind in ("iam_role_builtin", "folder_policy_grant_constraints"):
            assert collector.envelope(kind, scope, service, fetch)["status"] == "collected"
    assert len(transport.calls) == 3
    assert all(method == "GET" for method, _ in transport.calls)
