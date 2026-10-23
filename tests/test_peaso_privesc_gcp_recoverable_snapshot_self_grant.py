"""A recoverable snapshot policy write can grant bounded recovery access."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator
from tests.test_peaso_privesc_schema_ext import snapshot


PROJECT = "projects/p1"
SOURCE = "user:alice@corp.com"
RESOURCE = PROJECT + "/global/recoverableSnapshots/backup-deleted-abc"
BASE = "https://www.googleapis.com/compute/beta/"
ENTRY = next(e for e in privesc.catalog()["entries"]
             if e["id"] == "gcp-compute-recoverablesnapshots-setiampolicy-recoverable-snapshot-self-grant")


def case(*, can_write=True, can_read=True, prior=False, policy_status="collected",
         status="READY", duplicate=False, list_status="collected", role=True):
    writer = {"name": PROJECT + "/roles/recoverablePolicyWriter", "includedPermissions":
              (["compute.recoverableSnapshots.setIamPolicy"] if can_write else []) +
              (["compute.recoverableSnapshots.getIamPolicy"] if can_read else [])}
    recovery = {"name": "roles/compute.storageAdmin", "includedPermissions":
                ["compute.recoverableSnapshots.recover"] if role else []}
    bindings = [{"role": writer["name"], "members": [SOURCE]}]
    if prior:
        bindings.append({"role": recovery["name"], "members": [SOURCE]})
    deleted = {"name": "backup-deleted-abc", "selfLink": BASE + RESOURCE,
               "status": status, "iamPolicy": {"etag": "BwU", "bindings": []},
               "_coverage": {"iamPolicy": {"status": policy_status}}}
    snap = snapshot("gcp", [
        ("project", PROJECT, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", PROJECT, [{"name": PROJECT, "bindings": bindings}]),
        ("iam_role", PROJECT, [writer, recovery]),
        ("recoverable_snapshot", PROJECT, [deleted, deepcopy(deleted)] if duplicate else [deleted], list_status),
        ("service_account", PROJECT, []),
        ("iam_deny_policy", PROJECT, [], "empty"),
        ("org_policy_effective", PROJECT, [], "empty"),
        ("group", PROJECT, [], "empty"),
        ("group_membership", PROJECT, [], "empty")])
    return [(tid, grant.confidence) for reach in Evaluator(GcpModel(snap), [ENTRY]).run()
            if reach.source.id == SOURCE for tid, grant in reach.targets.items()]


def test_recoverable_snapshot_self_grant_requires_exact_ready_resource_and_role():
    result = case()
    assert len(result) == 1
    assert result[0][0].startswith("gcp_verified_authority:possible-recoverable-snapshot-self-grant:" + RESOURCE)
    assert result[0][1] == "conditional"
    assert case(can_write=False) == []
    assert case(prior=True) == []
    assert case(duplicate=True) == []
    assert case(can_read=False)[0][1] == "unknown"
    assert case(policy_status="denied")[0][1] == "unknown"
    assert case(status="FAILED")[0][1] == "unknown"
    assert case(role=False)[0][1] == "unknown"
    assert case(list_status="denied")[0][1] == "unknown"
