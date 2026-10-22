"""Organization policy write yields only a new, grantable permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


ORG = "organizations/654321"
SOURCE = "user:operator@example.com"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-resourcemanager-organizations-setiampolicy")


def envelope(kind, rows):
    return {"type": kind, "scope": ORG,
            "status": "collected" if rows else "empty", "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("organization", [{"name": ORG, "state": "ACTIVE"}]),
        envelope("iam_policy", [{"name": ORG, "_representation": "full", "bindings": [
            {"role": "roles/resourcemanager.organizationAdmin", "members": [SOURCE]}]}]),
        envelope("iam_role_builtin", [
            {"name": "roles/resourcemanager.organizationAdmin", "includedPermissions": [
                "resourcemanager.organizations.setIamPolicy",
                "resourcemanager.projects.setIamPolicy"]},
            {"name": "roles/orgpolicy.policyAdmin", "includedPermissions": [
                "orgpolicy.policy.set"]}]),
        envelope("iam_role", []), envelope("iam_deny_policy", []),
        envelope("organization_policy_grant_constraints", []),
        envelope("policy_binding", []),
        envelope("principal_access_boundary_policy", []),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_org_admin_can_gain_policy_setting_when_lacking_it():
    assert reached(case()) == [(
        "gcp_verified_authority:possible-org-policy-self-grant:" + ORG, "conditional")]


def test_existing_policy_admin_or_missing_writer_is_not_new_access():
    snap = case()
    snap["collections"][1]["items"][0]["bindings"].append(
        {"role": "roles/orgpolicy.policyAdmin", "members": [SOURCE]})
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["bindings"] = []
    assert reached(snap) == []


def test_incomplete_or_conflicting_organization_facts_are_not_definite():
    for change in (
        lambda s: s["collections"][0]["items"][0].update({"state": "DELETE_REQUESTED"}),
        lambda s: s["collections"][0]["items"].append(deepcopy(s["collections"][0]["items"][0])),
        lambda s: s["collections"][1]["items"][0].pop("_representation"),
        lambda s: s["collections"][1]["items"][0]["bindings"][0].update({
            "condition": {"expression": "request.time < timestamp('2020-01-01T00:00:00Z')"}}),
        lambda s: s["collections"][5]["items"].append({
            "name": ORG + "/policies/iam.allowedPolicyMemberDomains",
            "constraint": "iam.allowedPolicyMemberDomains", "spec": {"rules": [{"values": {
                "allowedValues": ["is:example.com"]}}]}}),
        lambda s: s["collections"][6]["items"].append({
            "name": ORG + "/locations/global/policyBindings/limited",
            "policyKind": "PRINCIPAL_ACCESS_BOUNDARY"}),
    ):
        snap = case(); change(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_organization_grant_inputs_are_read_only(monkeypatch):
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
            if "/roles/" in url:
                return {"name": url.removeprefix("https://iam.googleapis.com/v1/"),
                        "includedPermissions": ["orgpolicy.policy.set"]}, "role"
            return {"name": url.removeprefix("https://orgpolicy.googleapis.com/v2/")
                    .removesuffix(":getEffectivePolicy"),
                    "spec": {"rules": [{"allowAll": True}]}}, "effective-policy"

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [ORG], "options": {
        "inventories": ["iam_role_builtin", "organization_policy_grant_constraints"],
        "include_inherited": False, "concurrency": 1}}, transport=transport)
    for kind, scope, service, fetch in collector.scope_jobs(ORG):
        if kind in ("iam_role_builtin", "organization_policy_grant_constraints"):
            assert collector.envelope(kind, scope, service, fetch)["status"] == "collected"
    assert len(transport.calls) == 6
    assert ("GET", "https://iam.googleapis.com/v1/roles/iam.denyAdmin") in transport.calls
    assert ("GET", "https://iam.googleapis.com/v1/roles/iam.organizationRoleAdmin") in transport.calls
    assert all(method == "GET" for method, _ in transport.calls)
