"""An instance policy write grants only a new instance-level permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
RESOURCE = PROJECT + "/zones/us-central1-a/instances/vm1"
BASE = "https://www.googleapis.com/compute/v1/"
ENTRY = next(e for e in privesc.catalog()["entries"] if e["id"] == "gcp-compute-instances-setiampolicy")


def case(*, policy_status="collected", prior_admin=False, can_write=True, can_read=True, duplicate=False):
    writer = {"name": PROJECT + "/roles/vmPolicyWriter", "includedPermissions":
              (["compute.instances.setIamPolicy"] if can_write else []) +
              (["compute.instances.getIamPolicy"] if can_read else [])}
    admin = {"name": "roles/compute.osAdminLogin", "includedPermissions":
             ["compute.instances.osLogin", "compute.instances.osAdminLogin"]}
    bindings = [{"role": writer["name"], "members": [SOURCE]}]
    if prior_admin:
        bindings.append({"role": admin["name"], "members": [SOURCE]})
    vm = {"name": "vm1", "zone": BASE + "projects/p1/zones/us-central1-a",
          "selfLink": BASE + RESOURCE, "status": "RUNNING",
          "iamPolicy": {"etag": "BwU", "bindings": []},
          "_coverage": {"iamPolicy": {"status": policy_status}}}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [writer, admin]),
        ("instance", PROJECT, [vm, deepcopy(vm)] if duplicate else [vm]),
        ("service_account", PROJECT, []),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_instance_policy_self_grant_is_bounded_to_new_vm_permission():
    result = case()
    assert len(result) == 1
    assert result[0][0].startswith("gcp_verified_authority:possible-instance-osadmin-self-grant:" + RESOURCE)
    assert result[0][1] == "conditional"
    assert case(can_write=False) == []
    assert case(prior_admin=True) == []
    assert case(duplicate=True) == []
    assert case(can_read=False)[0][1] == "unknown"
    assert case(policy_status="access_denied")[0][1] == "unknown"
