"""A hub or group policy write can add only new group-use authority."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_resource_self_grant import ncc_group_candidates, select
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
HUB = PROJECT + "/locations/global/hubs/core"
GROUP = HUB + "/groups/default"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/nccPolicyWriter"
GROUP_ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                   "gcp-networkconnectivity-groups-setiampolicy-group-self-grant")
HUB_ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
                 "gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case(*, hub_writer=False):
    prefix = "networkconnectivity.hubs" if hub_writer else "networkconnectivity.groups"
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions": [
            prefix + ".setIamPolicy", prefix + ".getIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("network_connectivity_hub", [{"name": HUB,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
        envelope("network_connectivity_hub_group", [{"name": GROUP,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snapshot, entry):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snapshot), [entry], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if not target.startswith(("unknown:", "unresolved:"))]


def selected(snapshot, entry):
    model = GcpModel(snapshot)
    model.current_entry = entry
    targets = ncc_group_candidates(model, hub_policy=entry is HUB_ENTRY)
    return select(model, targets, model.principals[SOURCE])


def test_exact_group_and_hub_policy_writes_each_enable_group_use():
    assert reached(case(), GROUP_ENTRY)[0][1] == "conditional"
    assert reached(case(hub_writer=True), HUB_ENTRY)[0][1] == "conditional"
    assert reached(case(), HUB_ENTRY) == []
    assert reached(case(hub_writer=True), GROUP_ENTRY) == []


def test_prior_access_from_group_hub_or_project_is_not_new():
    for index in (2, 7, 8):
        snap = case()
        binding = {"role": "roles/networkconnectivity.groupUser", "members": [SOURCE]}
        if index == 2:
            snap["collections"][index]["items"][0]["bindings"].append(binding)
        else:
            snap["collections"][index]["items"][0]["iamPolicy"]["bindings"].append(binding)
        assert reached(snap, GROUP_ENTRY) == []
        hub_snap = case(hub_writer=True)
        if index == 2:
            hub_snap["collections"][index]["items"][0]["bindings"].append(binding)
        else:
            hub_snap["collections"][index]["items"][0]["iamPolicy"]["bindings"].append(binding)
        assert reached(hub_snap, HUB_ENTRY) == []


def test_wrong_group_duplicate_and_missing_policies_do_not_become_definite():
    snap = case()
    snap["collections"][8]["items"][0]["name"] = GROUP.replace("/hubs/core/", "/hubs/other/")
    assert reached(snap, GROUP_ENTRY) == []
    snap = case()
    snap["collections"][8]["items"].append(deepcopy(snap["collections"][8]["items"][0]))
    assert reached(snap, GROUP_ENTRY) == []
    for index in (7, 8):
        snap = case()
        snap["collections"][index]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
        assert reached(snap, GROUP_ENTRY) == []
        assert reached(snap, HUB_ENTRY) == []


def test_resource_condition_is_checked_at_mutated_policy():
    snap = case()
    snap["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + GROUP + "'"}
    assert reached(snap, GROUP_ENTRY)[0][1] == "conditional"
    snap["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + HUB + "'"}
    assert reached(snap, GROUP_ENTRY) == []
    snap = case(hub_writer=True)
    snap["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + HUB + "'"}
    assert reached(snap, HUB_ENTRY)[0][1] == "conditional"


def test_hub_policy_route_keeps_missing_group_evidence_unresolved():
    snap = case(hub_writer=True)
    path = next(iter(selected(snap, HUB_ENTRY).values()))
    assert path[0] == "conditional"
    snap["collections"][8]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert next(iter(selected(snap, HUB_ENTRY).values()))[0] == "unknown"
    snap = case(hub_writer=True)
    snap["collections"][1]["items"][0]["includedPermissions"].remove(
        "networkconnectivity.hubs.getIamPolicy")
    assert next(iter(selected(snap, HUB_ENTRY).values()))[0] == "unknown"
    snap = case(hub_writer=True)
    snap["collections"][8]["items"].clear()
    assert selected(snap, HUB_ENTRY) == {}
