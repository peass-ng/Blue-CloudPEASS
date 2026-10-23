"""A service-account swap needs one exact VM and a post-swap execution path."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-setserviceaccount-actas")


def case(*, status="TERMINATED", stop=True, start=True, change=True, actas=True,
         metadata=True, oslogin=False, public=False, duplicate=False, same_attached=False):
    permissions = (["compute.instances.setServiceAccount"] if change else []) + \
                  (["compute.instances.start"] if start else []) + \
                  (["compute.instances.stop"] if stop else []) + \
                  (["compute.instances.get", "compute.instances.setMetadata"] if metadata else []) + \
                  (["compute.instances.osLogin"] if oslogin else [])
    role = {"name": PROJECT + "/roles/vmSwap", "includedPermissions": permissions}
    policy = {"name": PROJECT, "bindings": [{"role": role["name"], "members": [SOURCE]}] +
              ([{"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}] if actas else [])}
    vm = {"name": "vm1", "status": status,
          "zone": BASE + "projects/p1/zones/us-central1-a",
          "selfLink": BASE + "projects/p1/zones/us-central1-a/instances/vm1",
          "serviceAccounts": [{"email": EMAIL if same_attached else "old@p1.iam.gserviceaccount.com",
                               "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
          "metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]},
          "networkInterfaces": [{"network": BASE + "projects/p1/global/networks/default",
                                 "accessConfigs": [{"natIP": "203.0.113.10"}] if public else []}]}
    firewall = {"name": "ssh", "network": BASE + "projects/p1/global/networks/default",
                "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123",
                               "commonInstanceMetadata": {"items": []}}]),
        ("iam_policy", PROJECT, [policy]), ("iam_role", PROJECT, [role]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("instance", PROJECT, [vm, dict(vm)] if duplicate else [vm]),
        ("firewall", PROJECT, [firewall] if public else [], "collected" if public else "empty"),
        ("effective_firewall", PROJECT, [{"network": BASE + "projects/p1/global/networks/default",
                                           "firewallPolicys": []}]),
        ("iam_deny_policy", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_swap_from_stopped_or_running_vm_requires_exact_lifecycle_and_metadata():
    assert case() == [(TARGET, "conditional")]
    assert case(status="RUNNING") == [(TARGET, "conditional")]
    assert case(actas=False) == []
    assert case(change=False) == []
    assert case(status="RUNNING", stop=False)[0][1] == "unknown"
    assert case(start=False)[0][1] == "unknown"
    assert case(metadata=False)[0][1] == "unknown"
    assert case(duplicate=True)[0][1] == "unknown"
    assert case(same_attached=True) == []


def test_swap_can_use_existing_oslogin_instead_of_metadata_write():
    assert case(metadata=False, oslogin=True, public=True) == [(TARGET, "conditional")]
    assert case(metadata=False, oslogin=True, public=False)[0][1] == "unknown"
