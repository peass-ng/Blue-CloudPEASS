"""IAP instance self-grants need exact VM and complete inherited policies."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
ROOT = PROJECT + "/iap_tunnel"
ZONE = ROOT + "/zones/us-central1-a"
RESOURCE = ZONE + "/instances/login1"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/iapWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-iap-tunnelinstances-setiampolicy-instance-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def policy(name, bindings=None, status="collected"):
    return {"name": name, "iamPolicy": {"bindings": bindings or []},
            "_coverage": {"iamPolicy": {"status": status}}}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": [
            "iap.tunnelInstances.setIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("instance", [{"name": "login1", "status": "RUNNING",
            "selfLink": "https://www.googleapis.com/compute/v1/" +
                        PROJECT + "/zones/us-central1-a/instances/login1"}]),
        envelope("iap_tunnel_policy", [policy(ROOT), policy(ZONE), policy(RESOURCE)]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_instance_and_complete_iap_policies_give_conditional_path():
    assert reached(case()) == [("gcp_verified_authority:possible-iap-instance-self-grant:" +
                                RESOURCE, "conditional")]
    snap = case()
    snap["collections"][-2]["items"][0]["status"] = "TERMINATED"
    assert reached(snap)[0][1] == "conditional"


def test_existing_access_or_absent_writer_is_not_escalation():
    for level in (0, 1, 2):
        snap = case()
        snap["collections"][-1]["items"][level]["iamPolicy"]["bindings"] = [
            {"role": "roles/iap.tunnelResourceAccessor", "members": [SOURCE]}]
        assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []


def test_policy_writer_condition_must_match_the_iap_instance():
    snap = case()
    binding = snap["collections"][2]["items"][0]["bindings"][0]
    binding["condition"] = {"expression": 'resource.name == "' + RESOURCE + '"'}
    assert reached(snap)[0][1] == "conditional"
    binding["condition"] = {"expression": 'resource.name == "' + RESOURCE.replace(
        "login1", "other") + '"'}
    assert reached(snap) == []


def test_incomplete_policy_or_wrong_vm_is_not_definite():
    for mutate in (
        lambda s: s["collections"][-1]["items"][0]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-1]["items"][1]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-1]["items"][2]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-2]["items"][0].update({"name": "other"}),
    ):
        snap = deepcopy(case()); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))
