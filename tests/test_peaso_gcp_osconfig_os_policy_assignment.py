"""Zonal OS policy assignment writes require an eligible exact VM."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_gcp_osconfig_guest_policy import case, collection, PROJECT, TARGET


ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-osconfig-ospolicyassignments-create")
ZONE = PROJECT + "/locations/us-central1-a"


def report(permission, *, assignments=(), status="empty"):
    snap = case((permission,))
    collection(snap, "os_inventory")["items"][0]["osInfo"] = {
        "osconfigAgentVersion": "20220427.00"}
    snap["collections"].append({"type": "osconfig_os_policy_assignment", "scope": PROJECT,
                                "status": status, "items": list(assignments)})
    return snap


def reaches(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() for target, grant in edge.targets.items()]


def test_zonal_create_and_update_allow_missing_reach_exact_attached_sa():
    for permission in ("osconfig.osPolicyAssignments.create",
                       "osconfig.osPolicyAssignments.update"):
        assert (TARGET, "conditional") in reaches(report(permission))


def test_wrong_zone_and_wrong_name_do_not_claim_a_definite_path():
    snap = report("osconfig.osPolicyAssignments.create")
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + PROJECT + "/locations/us-central1-b'"}
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.osPolicyAssignments.update")
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + ZONE + "/osPolicyAssignments/other'"}
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))


def test_exact_existing_assignment_and_unknown_inventory():
    name = ZONE + "/osPolicyAssignments/production"
    snap = report("osconfig.osPolicyAssignments.update", assignments=({"name": name},), status="collected")
    assert (TARGET, "conditional") in reaches(snap)
    snap = report("osconfig.osPolicyAssignments.update", status="denied")
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))


def test_ga_agent_and_tasks_feature_are_required():
    snap = report("osconfig.osPolicyAssignments.create")
    collection(snap, "os_inventory")["items"][0]["osInfo"]["osconfigAgentVersion"] = "20200101.00"
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.osPolicyAssignments.create")
    collection(snap, "instance")["items"][0]["metadata"]["items"].append(
        {"key": "osconfig-disabled-features", "value": "tasks"})
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_stopped_vm_or_narrow_oauth_scope_cannot_be_confirmed():
    snap = report("osconfig.osPolicyAssignments.create")
    collection(snap, "instance")["items"][0]["status"] = "TERMINATED"
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.osPolicyAssignments.create")
    collection(snap, "instance")["items"][0]["serviceAccounts"][0]["scopes"] = []
    assert TARGET not in [target for target, _ in reaches(snap)]
