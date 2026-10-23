"""Snapshot policy writes can yield bounded use on exact global or regional snapshots."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-compute-snapshots-setiampolicy-snapshot-self-grant")


def case(*, regional=False, can_write=True, can_read=True, prior=False,
         policy_status="collected", status="READY", duplicate=False, role=True):
    location = "regions/us-central1" if regional else "global"
    resource = f"{PROJECT}/{location}/snapshots/backup"
    writer = {"name": PROJECT + "/roles/snapshotPolicyWriter", "includedPermissions":
              (["compute.snapshots.setIamPolicy"] if can_write else []) +
              (["compute.snapshots.getIamPolicy"] if can_read else [])}
    reader = {"name": "roles/compute.storageAdmin", "includedPermissions":
              ["compute.snapshots.useReadOnly"] if role else []}
    bindings = [{"role": writer["name"], "members": [SOURCE]}]
    if prior:
        bindings.append({"role": reader["name"], "members": [SOURCE]})
    image = {"name": "backup", "selfLink": "https://www.googleapis.com/compute/v1/" + resource,
             "status": status, "iamPolicy": {"etag": "BwU", "bindings": []},
             "_coverage": {"iamPolicy": {"status": policy_status}}}
    if regional:
        image["region"] = "https://www.googleapis.com/compute/v1/projects/p1/regions/us-central1"
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [writer, reader]),
        ("snapshot", PROJECT, [image, deepcopy(image)] if duplicate else [image]),
        ("service_account", PROJECT, []),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_global_and_regional_snapshot_self_grant_paths():
    for regional in (False, True):
        result = case(regional=regional)
        assert len(result) == 1
        assert result[0][0].startswith("gcp_verified_authority:possible-snapshot-self-grant:")
        assert result[0][1] == "conditional"
    assert case(can_write=False) == []
    assert case(prior=True) == []
    assert case(duplicate=True) == []
    assert case(can_read=False)[0][1] == "unknown"
    assert case(policy_status="denied")[0][1] == "unknown"
    assert case(status="FAILED")[0][1] == "unknown"
    assert case(role=False)[0][1] == "unknown"
