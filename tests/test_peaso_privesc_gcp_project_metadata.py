"""Project metadata takeover needs an inheriting VM and a usable route."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/"
ZONE = "us-central1-a"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-projects-setcommoninstancemetadata")


def case(*, write=True, get=True, actas=True, reset=True, public=False, org_enforced=False,
         vm_metadata=None, zone_metadata=None, settings=True, scopes=None, duplicate=False,
         state="RUNNING", settings_status="collected"):
    permissions = (["compute.projects.setCommonInstanceMetadata"] if write else []) + \
                  (["compute.projects.get"] if get else []) + \
                  (["iam.serviceAccounts.actAs"] if actas else []) + \
                  (["compute.instances.reset"] if reset else [])
    role = {"name": PROJECT + "/roles/projectMetadata", "includedPermissions": permissions}
    vm = {"name": "vm1", "status": state, "zone": BASE + f"projects/p1/zones/{ZONE}",
          "selfLink": BASE + f"projects/p1/zones/{ZONE}/instances/vm1",
          "metadata": {"items": vm_metadata or []},
          "serviceAccounts": [{"email": EMAIL, "scopes": scopes if scopes is not None else
                               ["https://www.googleapis.com/auth/cloud-platform"]}],
          "networkInterfaces": [{"network": BASE + "projects/p1/global/networks/default",
                                 "accessConfigs": [{"natIP": "203.0.113.10"}] if public else []}]}
    firewall = {"name": "ssh", "network": BASE + "projects/p1/global/networks/default",
                "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    org = {"constraint": "compute.requireOsLogin", "spec": {"rules": [{"enforce": True}]}}
    settings_rows = [{"_zone": ZONE, "zone": BASE + f"projects/p1/zones/{ZONE}",
                      "metadata": {"items": zone_metadata or {}}}] if settings else []
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123",
                               "commonInstanceMetadata": {"items": []}}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", PROJECT, [role]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("instance", PROJECT, [vm, dict(vm)] if duplicate else [vm]),
        ("instance_settings", PROJECT, settings_rows, settings_status),
        ("firewall", PROJECT, [firewall] if public else [], "collected" if public else "empty"),
        ("effective_firewall", PROJECT, [{"network": BASE + "projects/p1/global/networks/default",
                                           "firewallPolicys": []}]),
        ("org_policy_effective", PROJECT, [org] if org_enforced else [],
         "collected" if org_enforced else "empty"),
        ("iam_deny_policy", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_project_startup_requires_exact_inheritance_and_a_boot_trigger():
    assert case() == [(TARGET, "conditional")]
    assert case(write=False) == []
    assert case(actas=False) == []
    assert case(get=False)[0][1] == "unknown"
    assert case(reset=False)[0][1] == "unknown"
    assert case(settings=False)[0][1] == "unknown"
    assert case(settings_status="denied", settings=False)[0][1] == "unknown"
    assert case(vm_metadata=[{"key": "startup-script", "value": "echo existing"}])[0][1] == "unknown"
    assert case(zone_metadata={"startup-script": "echo existing"})[0][1] == "unknown"
    assert case(zone_metadata=[{"key": "startup-script"}])[0][1] == "unknown"
    assert case(scopes=["https://www.googleapis.com/auth/devstorage.read_only"])[0][1] == "unknown"
    assert case(duplicate=True)[0][1] == "unknown"
    assert case(org_enforced=True) == [(TARGET, "conditional")]


def test_project_ssh_key_route_keeps_script_blockers_separate():
    assert case(reset=False, public=True) == [(TARGET, "conditional")]
    assert case(reset=False, public=True, settings=False) == [(TARGET, "conditional")]
    assert case(reset=False, public=True, zone_metadata={"startup-script": "existing"}) == [(TARGET, "conditional")]
    assert case(reset=False, public=True, vm_metadata=[{"key": "block-project-ssh-keys", "value": "TRUE"}])[0][1] == "unknown"
    assert case(reset=False, public=True, vm_metadata=[{"key": "enable-oslogin", "value": "TRUE"}])[0][1] == "unknown"
    assert case(reset=False, public=True, org_enforced=True)[0][1] == "unknown"
