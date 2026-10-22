"""A new job must inherit create and execute access in one project."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

from test_peaso_privesc_audit_fixes import _GSA, snapshot


SOURCE = "user:operator@example.com"
ENTRY = next(entry for entry in privesc.catalog()["entries"]
             if entry["id"] == "gcp-run-jobs-create-run-actas")


def scenario(*, create=True, run=True, split=False, actas=True, api="ENABLED",
             run_condition=None):
    project = "projects/p1"
    other = "projects/p2" if split else project
    create_role = project + "/roles/createJob"
    run_role = other + "/roles/runJob"
    collections = [
        ("project", project, [{"projectId": "p1", "name": "projects/123"}], "collected"),
        ("iam_role", project, [{"name": create_role, "includedPermissions":
                                ["run.jobs.create"] if create else []}], "collected"),
        ("iam_policy", project, [{"name": project, "bindings": [
            {"role": create_role, "members": [SOURCE]}]}], "collected"),
        ("service_account", project, [{"email": _GSA, "projectId": "p1",
            "name": project + "/serviceAccounts/" + _GSA,
            "iamPolicy": {"bindings": ([{"role": "roles/iam.serviceAccountUser",
                                        "members": [SOURCE]}] if actas else [])}}], "collected"),
        ("service_usage", project, ([{"name": project + "/services/run.googleapis.com",
                                       "state": api}] if api is not None else []),
         "collected" if api is not None else "denied"),
        ("iam_deny_policy", project, [], "empty"),
        ("service_perimeter", project, [], "empty"),
    ]
    if split:
        collections += [("project", other, [{"projectId": "p2", "name": "projects/456"}], "collected")]
    collections += [
        ("iam_role", other, [{"name": run_role, "includedPermissions":
                              ["run.jobs.run"] if run else []}], "collected"),
        ("iam_policy", other, [{"name": other, "bindings": [
            {"role": run_role, "members": [SOURCE], **({"condition": {
                "expression": run_condition}} if run_condition else {})}]}], "collected"),
    ]
    return snapshot("gcp", collections)


def reached(**kwargs):
    edges = Evaluator(GcpModel(scenario(**kwargs)), [ENTRY], include_unknown=True).run()
    return {tid: grant.confidence for edge in edges if edge.source.id == SOURCE
            for tid, grant in edge.targets.items()}


def test_create_and_run_same_project_with_actas_and_enabled_api():
    assert reached()["serviceAccount:" + _GSA] == "conditional"


def test_separate_projects_or_missing_grants_do_not_make_a_job_path():
    for options in ({"split": True}, {"create": False}, {"run": False}, {"actas": False}):
        assert reached(**options).get("serviceAccount:" + _GSA) != "conditional"


def test_disabled_or_unreadable_api_does_not_make_a_confirmed_path():
    for api in ("DISABLED", None):
        assert reached(api=api).get("serviceAccount:" + _GSA) != "conditional"


def test_job_name_condition_is_kept_unresolved_for_a_future_job():
    result = reached(run_condition='resource.name == "projects/p1/locations/us/jobs/existing"')
    assert result.get("serviceAccount:" + _GSA) != "conditional"
    assert any(name.startswith("unresolved:") and confidence == "unknown"
               for name, confidence in result.items())
