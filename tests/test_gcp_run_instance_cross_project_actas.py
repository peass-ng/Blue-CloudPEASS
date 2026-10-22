"""Cross-project instance attachment needs a real host path and service-agent access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _cross_project_run_snapshot


HOST = "projects/host"
TARGET = "projects/target"
INSTANCE = HOST + "/locations/europe-west4/instances/worker"
ACCOUNT = "serviceAccount:a@target.iam.gserviceaccount.com"
ENTRY = next(entry for entry in privesc.catalog()["entries"] if entry["id"] ==
             "gcp-run-instances-create-update-cross-project-actas")


def scenario(*, create=True, update=False, start=False, state="CONDITION_SUCCEEDED",
             policy=False, agent_grant=True, host_access=True, disabled=False,
             deleted=False, host_number=True):
    snap = _cross_project_run_snapshot(policy=policy, agent_grant=agent_grant,
                                       host_access=host_access, disabled=disabled)
    collections = {row["type"]: row for row in snap["collections"]}
    permissions = (["run.instances.create"] if create else [])
    permissions += (["run.instances.update"] if update else [])
    permissions += (["run.instances.start"] if start else [])
    collections["iam_role"]["items"][0]["includedPermissions"] = permissions if host_access else []
    if update:
        item = {"name": INSTANCE, "serviceAccount": "a@target.iam.gserviceaccount.com",
                "terminalCondition": {"state": state}, "reconciling": False,
                "iamPolicy": {"bindings": []},
                "_coverage": {"iamPolicy": {"status": "collected"}}}
        if deleted:
            item["deleteTime"] = "2026-01-01T00:00:00Z"
        snap["collections"].append({"type": "cloudrun_instance", "scope": HOST,
                                    "items": [item], "status": "collected"})
    if not host_number:
        collections["project"]["items"][0]["name"] = HOST
    return snap


def reached(**kwargs):
    edges = Evaluator(GcpModel(scenario(**kwargs)), [ENTRY], include_unknown=True).run()
    return {target: grant.confidence for edge in edges if edge.source.id == "user:u@x.com"
            for target, grant in edge.targets.items()}


def test_create_and_exact_update_are_possible_cross_project_paths():
    assert reached()[ACCOUNT] == "conditional"
    assert reached(create=False, update=True)[ACCOUNT] == "conditional"
    assert reached(create=False, update=True, start=True, state="CONDITION_FAILED")[ACCOUNT] == "conditional"


def test_stopped_or_deleted_instance_does_not_supply_a_reportable_update_path():
    assert reached(create=False, update=True, state="CONDITION_FAILED").get(ACCOUNT) != "conditional"
    assert reached(create=False, update=True, deleted=True).get(ACCOUNT) != "conditional"


def test_policy_agent_and_host_grant_are_required():
    assert reached(policy=True).get(ACCOUNT) != "conditional"
    assert reached(agent_grant=False).get(ACCOUNT) != "conditional"
    assert reached(host_access=False).get(ACCOUNT) != "conditional"
    assert reached(disabled=True).get(ACCOUNT) != "conditional"
    assert reached(host_number=False).get(ACCOUNT) != "conditional"
