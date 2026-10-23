"""Patch jobs and deployments reach only eligible attached VM identities."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_gcp_osconfig_guest_policy import case, collection, PROJECT, TARGET


ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-osconfig-patchjobs-exec")
DEPLOYMENT = PROJECT + "/patchDeployments/daily"


def report(permission, *, deployments=(), status="empty"):
    snap = case((permission,))
    collection(snap, "os_inventory")["items"][0]["osInfo"] = {
        "shortName": "ubuntu", "version": "22.04", "osconfigAgentVersion": "20220427.00"}
    snap["collections"].append({"type": "os_patch_deployment", "scope": PROJECT,
                                "status": status, "items": list(deployments)})
    return snap


def reaches(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() for target, grant in edge.targets.items()]


def test_one_shot_and_new_schedule_reach_eligible_vm():
    for permission in ("osconfig.patchJobs.exec", "osconfig.patchDeployments.create"):
        assert (TARGET, "conditional") in reaches(report(permission))


def test_update_requires_exact_existing_active_schedule():
    snap = report("osconfig.patchDeployments.update", deployments=({
        "name": DEPLOYMENT, "state": "ACTIVE", "recurringSchedule": {"frequency": "DAILY"}},),
        status="collected")
    assert (TARGET, "conditional") in reaches(snap)
    collection(snap, "os_patch_deployment")["items"][0]["state"] = "PAUSED"
    assert TARGET not in [target for target, _ in reaches(snap)]
    collection(snap, "os_patch_deployment")["items"] = []
    collection(snap, "os_patch_deployment")["status"] = "empty"
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_wrong_name_condition_keeps_only_unknown_possibility():
    snap = report("osconfig.patchDeployments.update", deployments=({
        "name": DEPLOYMENT, "state": "ACTIVE", "recurringSchedule": {"frequency": "DAILY"}},),
        status="collected")
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + PROJECT + "/patchDeployments/other'"}
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))


def test_disabled_tasks_stale_agent_and_unpatchable_os_are_not_positive():
    snap = report("osconfig.patchJobs.exec")
    collection(snap, "instance")["items"][0]["metadata"]["items"].append(
        {"key": "osconfig-disabled-features", "value": "tasks"})
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.patchJobs.exec")
    collection(snap, "os_inventory")["items"][0]["updateTime"] = "2026-10-20T10:30:00Z"
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.patchJobs.exec")
    collection(snap, "os_inventory")["items"][0]["osInfo"]["shortName"] = "cos"
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_unknown_os_does_not_disappear_or_claim_execution():
    snap = report("osconfig.patchJobs.exec")
    collection(snap, "os_inventory")["items"][0]["osInfo"] = {}
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))
