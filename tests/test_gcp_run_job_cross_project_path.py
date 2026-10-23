"""Cross-project job execution needs one executable host project."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _cross_project_run_snapshot


ENTRY = next(entry for entry in privesc.catalog()["entries"] if entry["id"] ==
             "gcp-run-jobs-create-run-cross-project-actas")
ACCOUNT = "serviceAccount:a@target.iam.gserviceaccount.com"


def reached(snap):
    edges = Evaluator(GcpModel(snap), [ENTRY], include_unknown=True).run()
    return {tid: grant.confidence for edge in edges if edge.source.id == "user:u@x.com"
            for tid, grant in edge.targets.items()}


def test_enabled_host_with_both_grants_and_cross_project_guards():
    assert reached(_cross_project_run_snapshot(False, mechanism="run_job"))[ACCOUNT] == "conditional"


def test_host_api_disabled_or_unreadable():
    for state in ("DISABLED", None):
        snap = _cross_project_run_snapshot(False, mechanism="run_job")
        usage = next(row for row in snap["collections"] if row["type"] == "service_usage")
        if state is None:
            usage["status"] = "denied"
            usage["items"] = []
        else:
            usage["items"][0]["state"] = state
        assert reached(snap).get(ACCOUNT) != "conditional"


def test_create_and_run_in_different_projects_do_not_form_one_path():
    snap = _cross_project_run_snapshot(False, mechanism="run_job")
    role = next(row for row in snap["collections"] if row["type"] == "iam_role")
    role["items"][0]["includedPermissions"] = ["run.jobs.create"]
    target = "projects/target"
    snap["collections"].extend([
        {"type": "iam_role", "scope": target, "status": "collected", "items": [
            {"name": target + "/roles/runJob", "includedPermissions": ["run.jobs.run"]}]},
        {"type": "iam_policy", "scope": target, "status": "collected", "items": [
            {"name": target, "bindings": [{"role": target + "/roles/runJob",
                                             "members": ["user:u@x.com"]}]}]},
    ])
    assert reached(snap).get(ACCOUNT) != "conditional"


def test_future_job_name_condition_remains_unresolved():
    snap = _cross_project_run_snapshot(False, mechanism="run_job")
    policy = next(row for row in snap["collections"] if row["type"] == "iam_policy")
    policy["items"][0]["bindings"][0]["condition"] = {
        "expression": 'resource.name == "projects/host/locations/us/jobs/existing"'}
    result = reached(snap)
    assert result.get(ACCOUNT) != "conditional"
    assert any(name.startswith("unresolved:") and confidence == "unknown"
               for name, confidence in result.items())
