"""OS administrator login must join an exact eligible VM and attached service account."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
EMAIL = "target@p1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
BASE = "https://www.googleapis.com/compute/v1/projects/p1/"


def test_osadminlogin_requires_enabled_running_vm_with_same_attached_sa():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-osadminlogin")
    role = {"name": "projects/p1/roles/osAdmin", "includedPermissions": [
        "compute.instances.osLogin", "compute.instances.osAdminLogin"]}
    policy = {"name": PROJECT, "bindings": [
        {"role": role["name"], "members": [SOURCE]},
        {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}]}
    vm = {"name": "login-vm", "status": "RUNNING", "zone": BASE + "zones/us-central1-a",
          "selfLink": BASE + "zones/us-central1-a/instances/login-vm",
          "serviceAccounts": [{"email": EMAIL, "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}],
          "metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]},
          "networkInterfaces": [{"network": BASE + "global/networks/default",
                                 "accessConfigs": [{"natIP": "203.0.113.10"}]}]}
    firewall = {"name": "allow-ssh", "network": BASE + "global/networks/default",
                "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}
    project_metadata = {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}

    def result(firewalls=None, selected_entry=entry):
        snap = snapshot("gcp", [
            ("project", PROJECT, [{"projectId": "p1", "name": "projects/123",
                                   "commonInstanceMetadata": project_metadata}]),
            ("iam_policy", PROJECT, [policy]), ("iam_role", PROJECT, [role]),
            ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
            ("instance", PROJECT, [vm]),
            ("firewall", PROJECT, [firewall] if firewalls is None else firewalls),
            ("effective_firewall", PROJECT, [{"network": BASE + "global/networks/default",
                                               "firewallPolicys": []}]),
            ("iam_deny_policy", PROJECT, [], "empty")])
        return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [selected_entry]).run()
                if reach.source.id == SOURCE for tid, grant in reach.targets.items()]

    assert result() == [(TARGET, "conditional")]
    vm["metadata"]["items"][0]["value"] = "FALSE"
    assert result() == []
    vm["metadata"]["items"][0]["value"] = "TRUE"
    assert len(result(firewalls=[])) == 1 and result(firewalls=[])[0][1] == "unknown"
    vm["metadata"]["items"].append({"key": "enable-oslogin", "value": "FALSE"})
    assert len(result()) == 1 and result()[0][1] == "unknown"
    vm["metadata"]["items"].pop()
    vm["metadata"]["items"].append({"key": "enable-oslogin-2fa", "value": "TRUE"})
    assert len(result()) == 1 and result()[0][1] == "unknown"
    vm["metadata"]["items"].pop()
    role["includedPermissions"].remove("compute.instances.osAdminLogin")
    assert result() == []
    standard_entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-oslogin")
    assert result(selected_entry=standard_entry) == [(TARGET, "conditional")]
    vm["metadata"]["items"][0]["value"] = "FALSE"
    assert result(selected_entry=standard_entry) == []


def test_cross_project_attached_sa_stays_unresolved():
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-osadminlogin")
    host_project = "projects/p2"
    role = {"name": "projects/p2/roles/osAdmin", "includedPermissions": [
        "compute.instances.osLogin", "compute.instances.osAdminLogin"]}
    vm = {"name": "cross-project", "status": "RUNNING",
          "selfLink": "https://www.googleapis.com/compute/v1/projects/p2/zones/us-central1-a/instances/cross-project",
          "serviceAccounts": [{"email": EMAIL}],
          "metadata": {"items": [{"key": "enable-oslogin", "value": "TRUE"}]}}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123"}]),
        ("project", host_project, [{"projectId": "p2", "name": "projects/456"}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": [
            {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}]}]),
        ("iam_policy", host_project, [{"name": host_project, "bindings": [
            {"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", host_project, [role]),
        ("service_account", PROJECT, [{"email": EMAIL, "projectId": "p1"}]),
        ("instance", host_project, [vm]),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("iam_deny_policy", host_project, [], "empty")])
    reaches = [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [entry]).run()
               if reach.source.id == SOURCE for tid, grant in reach.targets.items()]
    assert len(reaches) == 1 and reaches[0][1] == "unknown"
