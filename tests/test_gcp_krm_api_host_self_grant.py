"""Config Controller self-grants require an exact host and new update access."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
HOST = PROJECT + "/locations/us-central1/krmApiHosts/controller1"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/hostPolicyWriter"
TECHNIQUE = "gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] == TECHNIQUE)


def envelope(kind, rows):
    return {"type": kind, "scope": PROJECT,
            "status": "collected" if rows else "empty", "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": [
            "krmapihosting.krmApiHosts.setIamPolicy"]}]),
        envelope("iam_role_builtin", [{"name": "roles/krmapihosting.admin",
                                      "includedPermissions": ["krmapihosting.krmApiHosts.update"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("krm_api_host", [{"name": HOST, "state": "RUNNING",
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_running_host_with_new_update_permission():
    assert reached(case()) == [(
        "gcp_verified_authority:possible-krm-api-host-self-grant:" + HOST,
        "conditional")]


def test_no_new_access_when_already_admin_or_writer_missing():
    snap = case()
    snap["collections"][-1]["items"][0]["iamPolicy"]["bindings"] = [
        {"role": "roles/krmapihosting.admin", "members": [SOURCE]}]
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []


def test_missing_or_conflicting_host_evidence_never_becomes_definite():
    for mutate in (
        lambda s: s["collections"][-1]["items"][0]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-1]["items"].append(
            deepcopy(s["collections"][-1]["items"][0])),
        lambda s: s["collections"][-1]["items"][0].update(
            {"name": HOST.replace("demo-project1", "foreign-project")}),
        lambda s: s["collections"][-1]["items"][0].update({"state": "UPDATING"}),
    ):
        snap = case(); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))
