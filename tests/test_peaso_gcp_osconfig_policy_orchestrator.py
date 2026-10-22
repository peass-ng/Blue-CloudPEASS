"""Orchestrator permissions reach only VMs under a ready parent."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_gcp_osconfig_guest_policy import case, collection, PROJECT, TARGET


ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-osconfig-policyorchestrators")
ORCHESTRATOR = PROJECT + "/locations/global/policyOrchestrators/fleet"


def report(permission, *, orchestrators=(), status="empty"):
    snap = case((permission,))
    collection(snap, "os_inventory")["items"][0]["osInfo"] = {
        "osconfigAgentVersion": "20220427.00"}
    snap["collections"].extend([
        {"type": "osconfig_policy_orchestrator", "scope": PROJECT, "status": status,
         "items": list(orchestrators)},
        {"type": "service_usage", "scope": PROJECT, "status": "collected",
         "items": [{"name": PROJECT + "/services/" + name + ".googleapis.com", "state": "ENABLED"}
                   for name in ("osconfig", "progressiverollout")]},
    ])
    policy = collection(snap, "iam_policy")["items"][0]
    for role, domain in (("roles/osconfig.serviceAgent", "gcp-sa-osconfig"),
                         ("roles/osconfig.rolloutServiceAgent", "gcp-sa-osconfig-rollout"),
                         ("roles/progressiverollout.serviceAgent", "gcp-sa-progrollout")):
        policy["bindings"].append({"role": role, "members": [
            "serviceAccount:service-1234@" + domain + ".iam.gserviceaccount.com"]})
    return snap


def reaches(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() for target, grant in edge.targets.items()]


def test_project_create_and_exact_existing_update_reach_attached_sa():
    assert (TARGET, "conditional") in reaches(report("osconfig.policyOrchestrators.create"))
    snap = report("osconfig.policyOrchestrators.update", orchestrators=({
        "name": ORCHESTRATOR},), status="collected")
    assert (TARGET, "conditional") in reaches(snap)


def test_missing_or_conditioned_service_agent_role_is_unresolved():
    snap = report("osconfig.policyOrchestrators.create")
    collection(snap, "iam_policy")["items"][0]["bindings"].pop()
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))
    snap = report("osconfig.policyOrchestrators.create")
    collection(snap, "iam_policy")["items"][0]["bindings"][-1]["condition"] = {
        "expression": "request.time < timestamp('2099-01-01T00:00:00Z')"}
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_missing_required_api_or_vm_feature_is_not_positive():
    snap = report("osconfig.policyOrchestrators.create")
    collection(snap, "service_usage")["items"].pop()
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.policyOrchestrators.create")
    collection(snap, "instance")["items"][0]["metadata"]["items"].append(
        {"key": "osconfig-disabled-features", "value": "tasks"})
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_update_without_inventory_or_different_name_is_not_definite():
    snap = report("osconfig.policyOrchestrators.update", status="denied")
    assert TARGET not in [target for target, _ in reaches(snap)]
    snap = report("osconfig.policyOrchestrators.update", status="empty")
    assert reaches(snap) == []
    snap = report("osconfig.policyOrchestrators.update", orchestrators=({
        "name": ORCHESTRATOR},), status="collected")
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + PROJECT +
                      "/locations/global/policyOrchestrators/other'"}
    assert TARGET not in [target for target, _ in reaches(snap)]


def test_folder_permission_without_quota_evidence_stays_unresolved():
    snap = report("osconfig.policyOrchestrators.create")
    folder = "folders/42"
    collection(snap, "project")["items"][0]["parent"] = folder
    collection(snap, "iam_policy")["items"][0]["bindings"][0]["members"] = []
    snap["collections"].extend([
        {"type": "folder", "scope": folder, "status": "collected",
         "items": [{"name": folder}]},
        {"type": "iam_policy", "scope": folder, "status": "collected",
         "items": [{"name": folder, "bindings": [{"role": PROJECT + "/roles/guestPolicyWriter",
                   "members": ["user:operator@example.com"]}]}]},
        {"type": "osconfig_policy_orchestrator", "scope": folder,
         "status": "empty", "items": []},
    ])
    bindings = next(row for row in snap["collections"]
                    if row["type"] == "iam_policy" and row["scope"] == folder)["items"][0]["bindings"]
    for role, domain in (("roles/osconfig.serviceAgent", "gcp-sa-osconfig"),
                         ("roles/osconfig.rolloutServiceAgent", "gcp-sa-osconfig-rollout"),
                         ("roles/progressiverollout.serviceAgent", "gcp-sa-progrollout")):
        bindings.append({"role": role, "members": [
            "serviceAccount:service-folder-42@" + domain + ".iam.gserviceaccount.com"]})
    assert TARGET not in [target for target, _ in reaches(snap)]
    assert any(target.startswith("unresolved:") for target, _ in reaches(snap))
