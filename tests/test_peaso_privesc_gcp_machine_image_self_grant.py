"""A machine-image policy write can gain only a bounded image-use permission."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
RESOURCE = PROJECT + "/global/machineImages/backup"
BASE = "https://www.googleapis.com/compute/v1/"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-compute-machineimages-setiampolicy-machine-image-self-grant")


def case(*, can_write=True, can_read=True, prior=False, policy_status="collected",
         image_status="READY", duplicate=False):
    writer = {"name": PROJECT + "/roles/machineImagePolicyWriter", "includedPermissions":
              (["compute.machineImages.setIamPolicy"] if can_write else []) +
              (["compute.machineImages.getIamPolicy"] if can_read else [])}
    reader = {"name": "roles/compute.admin", "includedPermissions":
              ["compute.machineImages.useReadOnly"]}
    bindings = [{"role": writer["name"], "members": [SOURCE]}]
    if prior:
        bindings.append({"role": reader["name"], "members": [SOURCE]})
    image = {"name": "backup", "selfLink": BASE + RESOURCE, "status": image_status,
             "iamPolicy": {"etag": "BwU", "bindings": []},
             "_coverage": {"iamPolicy": {"status": policy_status}}}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [writer, reader]),
        ("machine_image", PROJECT, [image, deepcopy(image)] if duplicate else [image]),
        ("service_account", PROJECT, []),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_machine_image_self_grant_needs_new_permission_and_readable_ready_policy():
    result = case()
    assert len(result) == 1
    assert result[0][0].startswith("gcp_verified_authority:possible-machine-image-self-grant:" + RESOURCE)
    assert result[0][1] == "conditional"
    assert case(can_write=False) == []
    assert case(prior=True) == []
    assert case(duplicate=True) == []
    assert case(can_read=False)[0][1] == "unknown"
    assert case(policy_status="access_denied")[0][1] == "unknown"
    assert case(image_status="CREATING")[0][1] == "unknown"
