"""Legacy guest-policy paths require a matching active VM and exact writes."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"
EMAIL = "victim@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
POLICY = PROJECT + "/guestPolicies/legacy"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-osconfig-guestpolicies-recipe")
BASE = "https://www.googleapis.com/compute/v1/" + PROJECT


def case(permissions=("osconfig.guestPolicies.create",), policies=()):
    role = {"name": PROJECT + "/roles/guestPolicyWriter", "includedPermissions": list(permissions)}
    vm = {"name": "managed-vm", "id": "123", "status": "RUNNING",
          "selfLink": BASE + "/zones/us-central1-a/instances/managed-vm",
          "metadata": {"items": [{"key": "enable-osconfig", "value": "TRUE"}]},
          "serviceAccounts": [{"email": EMAIL,
                               "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"name": "projects/1234", "projectId": "p1",
                               "commonInstanceMetadata": {"items": []}}]),
        ("iam_role", PROJECT, [role]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role["name"], "members": [SOURCE]}]}]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("instance", PROJECT, [vm]),
        ("os_inventory", PROJECT, [{"name": PROJECT + "/locations/us-central1-a/instances/123/inventory",
                                    "instanceName": "managed-vm", "updateTime": "2026-10-22T10:30:00Z"}]),
        ("osconfig_guest_policy", PROJECT, list(policies), "collected" if policies else "empty"),
        ("osconfig_project_feature_settings", PROJECT, [{
            "name": PROJECT + "/locations/global/projectFeatureSettings",
            "patchAndConfigFeatureSet": "OSCONFIG_C"}]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
    ])
    snap["created_at"] = "2026-10-22T11:00:00Z"
    return snap


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if target == TARGET]


def unresolved(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if target.startswith("unresolved:")]


def collection(snap, kind):
    return next(row for row in snap["collections"] if row["type"] == kind)


def test_create_path_requires_running_enabled_recent_agent_and_exact_sa():
    assert reached(case()) == [(TARGET, "conditional")]
    for change in (lambda s: collection(s, "instance")["items"][0].update(status="TERMINATED"),
                   lambda s: collection(s, "instance")["items"][0]["metadata"]["items"][0].update(value="FALSE"),
                   lambda s: collection(s, "os_inventory")["items"][0].update(updateTime="2026-10-20T10:30:00Z"),
                   lambda s: collection(s, "instance")["items"][0]["serviceAccounts"][0].update(scopes=[]),
                   lambda s: collection(s, "os_inventory").update(status="denied", items=[])):
        snap = case()
        change(snap)
        assert reached(snap) != [(TARGET, "conditional")]
    snap = case()
    collection(snap, "instance")["items"][0]["metadata"]["items"][0]["value"] = "FALSE"
    assert reached(snap) == []
    snap = case()
    collection(snap, "osconfig_project_feature_settings")["items"][0]["patchAndConfigFeatureSet"] = "OSCONFIG_B"
    assert reached(snap) == [] and len(unresolved(snap)) == 1
    snap = case()
    collection(snap, "project")["items"][0]["commonInstanceMetadata"]["items"] = [
        {"key": "osconfig-disabled-features", "value": "tasks,guestpolicies"}]
    assert reached(snap) == []


def test_update_path_requires_an_exact_existing_policy_and_remains_unresolved():
    policy = {"name": POLICY, "recipes": [{"name": "app", "version": "1.0",
                                           "desiredState": "UPDATED", "updateSteps": [{"scriptRun": {"script": "id"}}]}]}
    snap = case(("osconfig.guestPolicies.update",), (policy,))
    assert reached(snap) == [] and len(unresolved(snap)) == 1
    collection(snap, "osconfig_guest_policy")["items"] = []
    collection(snap, "osconfig_guest_policy")["status"] = "empty"
    assert reached(snap) == []


def test_exact_policy_condition_and_missing_inventory_do_not_claim_execution():
    policy = {"name": POLICY, "recipes": []}
    snap = case(("osconfig.guestPolicies.update",), (policy,))
    binding = collection(snap, "iam_policy")["items"][0]["bindings"][0]
    binding["condition"] = {"expression": "resource.name == '" + POLICY + "'"}
    assert reached(snap) == [] and len(unresolved(snap)) == 1
    binding["condition"] = {"expression": "resource.name == '" + POLICY + "-other'"}
    assert reached(snap) == []
    snap = case(("osconfig.guestPolicies.update",), (policy,))
    collection(snap, "osconfig_guest_policy").update(status="denied", items=[])
    assert reached(snap) == [] and len(unresolved(snap)) == 1


def test_wrong_sa_or_duplicate_vm_identity_is_not_a_definite_path():
    snap = case()
    collection(snap, "instance")["items"][0]["serviceAccounts"][0]["email"] = "other@p1.iam.gserviceaccount.com"
    assert reached(snap) == []
    snap = case()
    collection(snap, "instance")["items"].append(deepcopy(collection(snap, "instance")["items"][0]))
    assert reached(snap) == [] and len(unresolved(snap)) == 1


def test_an_eligible_vm_is_kept_when_another_attached_vm_is_disabled():
    snap = case()
    second = deepcopy(collection(snap, "instance")["items"][0])
    second["name"] = "disabled-vm"
    second["id"] = "456"
    second["selfLink"] = BASE + "/zones/us-central1-a/instances/disabled-vm"
    second["metadata"]["items"][0]["value"] = "FALSE"
    collection(snap, "instance")["items"].append(second)
    assert reached(snap) == [(TARGET, "conditional")]


def test_project_metadata_can_enable_the_matching_vm():
    snap = case()
    collection(snap, "instance")["items"][0]["metadata"] = {"items": []}
    collection(snap, "project")["items"][0]["commonInstanceMetadata"]["items"] = [
        {"key": "enable-osconfig", "value": "TRUE"}]
    assert reached(snap) == [(TARGET, "conditional")]
