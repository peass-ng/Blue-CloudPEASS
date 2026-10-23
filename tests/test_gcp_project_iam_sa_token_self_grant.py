"""Project IAM self-grant reaches only named, enabled service accounts."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_gcp_project_iam_self_grant import PROJECT, SOURCE, case


EMAIL = "worker@demo-project1.iam.gserviceaccount.com"
ACCOUNT = "serviceAccount:" + EMAIL
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-projects-setiampolicy-sa-token")


def scenario():
    snap = case()
    snap["collections"][2]["items"].append({
        "name": "roles/iam.serviceAccountTokenCreator",
        "includedPermissions": ["iam.serviceAccounts.getAccessToken"]})
    snap["collections"].append({"type": "service_account", "scope": PROJECT,
        "status": "collected", "items": [{
            "name": PROJECT + "/serviceAccounts/" + EMAIL,
            "email": EMAIL, "projectId": "demo-project1", "disabled": False,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]})
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_project_writer_can_gain_token_access_to_named_service_account():
    assert reached(scenario()) == [(ACCOUNT, "conditional")]


def test_existing_token_access_or_missing_writer_is_not_new_impersonation():
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"].append({
        "role": "roles/iam.serviceAccountTokenCreator", "members": [SOURCE]})
    assert reached(snap) == []
    snap = scenario()
    snap["collections"][7]["items"][0]["iamPolicy"]["bindings"].append({
        "role": "roles/iam.serviceAccountTokenCreator", "members": [SOURCE]})
    assert reached(snap) == []
    snap = scenario()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_disabled_account_or_missing_token_role_is_not_definite():
    snap = scenario()
    snap["collections"][7]["items"][0]["disabled"] = True
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap = scenario()
    snap["collections"][2]["items"].pop()
    assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_incomplete_policy_and_member_restrictions_stay_unresolved():
    for change in (
        lambda s: s["collections"][0]["items"][0].update({"state": "DELETE_REQUESTED"}),
        lambda s: s["collections"][0]["items"].append(deepcopy(s["collections"][0]["items"][0])),
        lambda s: s["collections"][1]["items"][0].pop("_representation"),
        lambda s: s["collections"][1]["items"][0]["bindings"][0].update({
            "condition": {"expression": "request.time < timestamp('2020-01-01T00:00:00Z')"}}),
        lambda s: s["collections"][7]["items"][0]["_coverage"]["iamPolicy"].update({"status": "denied"}),
        lambda s: s["collections"][5]["items"].append({
            "name": PROJECT + "/policies/iam.allowedPolicyMemberDomains",
            "constraint": "iam.allowedPolicyMemberDomains",
            "spec": {"rules": [{"values": {"allowedValues": ["is:example.com"]}}]}}),
        lambda s: s["collections"][6]["items"].append({
            "name": PROJECT + "/locations/global/policyBindings/limited",
            "policyKind": "PRINCIPAL_ACCESS_BOUNDARY"}),
    ):
        snap = scenario(); change(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_token_minting_deny_policy_blocks_or_downgrades_path():
    snap = scenario()
    rule = {"deniedPrincipals": [SOURCE],
            "deniedPermissions": ["iam.googleapis.com/serviceAccounts.getAccessToken"]}
    snap["collections"][4]["items"].append({
        "name": "policies/token-deny", "rules": [{"denyRule": rule}]})
    assert reached(snap) == []
    rule["denialCondition"] = {"expression": "resource.name.startsWith('projects/')"}
    assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_token_grant_inputs_are_collected_without_mutation(monkeypatch):
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
            if url.endswith("/serviceAccounts"):
                return {"accounts": [{"name": PROJECT + "/serviceAccounts/" + EMAIL,
                                       "email": EMAIL, "projectId": "demo-project1"}]}, "list"
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, "policy"
            return {"name": url.removeprefix("https://iam.googleapis.com/v1/"),
                    "includedPermissions": ["iam.serviceAccounts.getAccessToken"]}, "role"

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["service_account", "iam_role_builtin"],
        "service_account_activity": False, "include_inherited": False,
        "concurrency": 1}}, transport=transport)
    for kind, scope, service, fetch in collector.scope_jobs(PROJECT):
        if kind in ("service_account", "iam_role_builtin"):
            assert collector.envelope(kind, scope, service, fetch)["status"] == "collected"
    assert ("GET", "https://iam.googleapis.com/v1/roles/iam.serviceAccountTokenCreator") in transport.calls
    assert ("POST", "https://iam.googleapis.com/v1/" + PROJECT +
            "/serviceAccounts/" + EMAIL + ":getIamPolicy") in transport.calls
    assert all(method == "GET" or method == "POST" and url.endswith(":getIamPolicy")
               for method, url in transport.calls)
