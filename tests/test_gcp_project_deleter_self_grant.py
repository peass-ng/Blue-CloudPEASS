"""Project IAM writers gain deletion rights only through a new role grant."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_gcp_project_iam_self_grant import PROJECT, SOURCE, case


ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-projects-setiampolicy-project-delete")


def scenario():
    snap = case()
    snap["collections"][2]["items"].append({
        "name": "roles/resourcemanager.projectDeleter",
        "includedPermissions": ["resourcemanager.projects.delete"]})
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_project_writer_can_grant_new_project_deletion_permission():
    assert reached(scenario()) == [(
        "gcp_verified_authority:possible-project-delete-self-grant:" + PROJECT, "conditional")]


def test_existing_deletion_access_or_missing_writer_does_not_escalate():
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"].append({
        "role": "roles/resourcemanager.projectDeleter", "members": [SOURCE]})
    assert reached(snap) == []
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_missing_role_or_restrictive_policy_is_not_definite():
    snap = scenario()
    snap["collections"][2]["items"].pop()
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][4]["items"].append({
        "name": "policies/conditional-project-delete",
        "rules": [{"denyRule": {
            "deniedPrincipals": [SOURCE],
            "deniedPermissions": ["resourcemanager.googleapis.com/projects.delete"],
            "denialCondition": {"expression": "resource.name.startsWith('projects/')"}}}]})
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][5]["items"].append({
        "name": PROJECT + "/policies/iam.allowedPolicyMemberDomains",
        "constraint": "iam.allowedPolicyMemberDomains",
        "spec": {"rules": [{"values": {"allowedValues": ["is:example.com"]}}]}})
    assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_project_deleter_role_is_collected_read_only(monkeypatch):
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
            return {"name": url.removeprefix("https://iam.googleapis.com/v1/"),
                    "includedPermissions": ["resourcemanager.projects.delete"]}, "role"

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["iam_role_builtin"], "include_inherited": False,
        "concurrency": 1}}, transport=transport)
    for kind, scope, service, fetch in collector.scope_jobs(PROJECT):
        if kind == "iam_role_builtin":
            assert collector.envelope(kind, scope, service, fetch)["status"] == "collected"
    assert ("GET", "https://iam.googleapis.com/v1/roles/resourcemanager.projectDeleter") in transport.calls
    assert all(method == "GET" for method, _ in transport.calls)
