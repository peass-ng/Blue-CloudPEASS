"""Instance metadata takeover needs an exact runnable or reachable VM."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-setmetadata-existing-vm")


def case(*, reset=True, get=True, write=True, public=False, org_enforced=False,
         scopes=None, duplicate=False, state="RUNNING"):
    permissions = (["compute.instances.setMetadata"] if write else []) + \
                  (["compute.instances.get"] if get else []) + \
                  (["compute.instances.reset"] if reset else [])
    role = {"name": PROJECT + "/roles/vmMetadata", "includedPermissions": permissions}
    vm = {"name": "vm1", "status": state, "zone": BASE + "projects/p1/zones/us-central1-a",
          "selfLink": BASE + "projects/p1/zones/us-central1-a/instances/vm1",
          "serviceAccounts": [{"email": EMAIL, "scopes": scopes if scopes is not None else
                               ["https://www.googleapis.com/auth/cloud-platform"]}],
          "networkInterfaces": [{"network": BASE + "projects/p1/global/networks/default",
                                 "accessConfigs": [{"natIP": "203.0.113.10"}] if public else []}]}
    firewall = {"name": "ssh", "network": BASE + "projects/p1/global/networks/default",
                "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    org = {"constraint": "compute.requireOsLogin", "spec": {"rules": [{"enforce": True}]}}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", PROJECT, [role]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("instance", PROJECT, [vm, dict(vm)] if duplicate else [vm]),
        ("firewall", PROJECT, [firewall] if public else [], "collected" if public else "empty"),
        ("effective_firewall", PROJECT, [{"network": BASE + "projects/p1/global/networks/default",
                                           "firewallPolicys": []}]),
        ("org_policy_effective", PROJECT, [org] if org_enforced else [],
         "collected" if org_enforced else "empty"),
        ("iam_deny_policy", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_metadata_startup_branch_requires_a_trigger_and_metadata_fingerprint():
    assert case() == [(TARGET, "conditional")]
    assert case(write=False) == []
    assert case(reset=False)[0][1] == "unknown"
    assert case(get=False)[0][1] == "unknown"
    assert case(duplicate=True)[0][1] == "unknown"
    assert case(scopes=["https://www.googleapis.com/auth/devstorage.read_only"])[0][1] == "unknown"
    assert case(org_enforced=True) == [(TARGET, "conditional")]


def test_metadata_ssh_branch_respects_route_and_oslogin_enforcement():
    assert case(reset=False, public=True) == [(TARGET, "conditional")]
    assert case(reset=False, public=True, org_enforced=True)[0][1] == "unknown"
