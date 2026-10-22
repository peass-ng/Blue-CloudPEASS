"""An instance update only counts when the controlled code can run."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _GSA, _gcp_attached


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"
INSTANCE = PROJECT + "/locations/europe-west4/instances/workload"
ENTRY = next(entry for entry in privesc.catalog()["entries"]
             if entry["id"] == "gcp-run-instances-create-update-actas")


def reached(*, state="CONDITION_SUCCEEDED", reconciling=False, start=False,
            deleted=False, grant_scope=PROJECT):
    role = PROJECT + "/roles/manageInstance"
    permissions = ["run.instances.update"] + (["run.instances.start"] if start else [])
    item = {"name": INSTANCE, "serviceAccount": _GSA,
            "terminalCondition": {"state": state}, "reconciling": reconciling,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}
    if deleted:
        item["deleteTime"] = "2026-01-01T00:00:00Z"
    model, target = _gcp_attached([
        ("iam_role", PROJECT, [{"name": role, "includedPermissions": permissions}], "collected"),
        ("iam_policy", grant_scope, [{"name": grant_scope, "bindings": [
            {"role": role, "members": [SOURCE]}]}], "collected"),
        ("cloudrun_instance", PROJECT, [item], "collected"),
    ])
    account = next(c for c in model.snapshot["collections"] if c["type"] == "service_account")
    account["items"][0]["iamPolicy"] = {"bindings": [
        {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]}]}
    model = GcpModel(model.snapshot)
    return [(edge.targets[target.id].confidence, edge.targets[target.id].conditions)
            for edge in Evaluator(model, [ENTRY], include_unknown=True).run()
            if edge.source.id == SOURCE and target.id in edge.targets]


def test_ready_instance_update_remains_a_conditional_path():
    assert reached() and reached()[0][0] == "conditional"


def test_stopped_or_unresolved_instance_needs_start_access():
    assert all(confidence == "unknown" for confidence, _ in reached(state="CONDITION_FAILED"))
    assert reached(state="CONDITION_FAILED", start=True)[0][0] == "conditional"
    assert all(confidence == "unknown" for confidence, _ in reached(reconciling=True))


def test_deleted_instance_cannot_supply_update_path():
    assert reached(deleted=True) == []
