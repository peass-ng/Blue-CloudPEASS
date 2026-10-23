"""Job overrides only become an escalation when recorded args can run code."""

from peaso.privesc.effective_permissions.gcp import GcpModel

from test_peaso_privesc_audit_fixes import _GSA, _gcp_attached


PROJECT = "projects/p1"
SOURCE = "user:operator@example.com"
JOB = PROJECT + "/locations/us-central1/jobs/worker"


def selected(*, command=None, state="CONDITION_SUCCEEDED", reconciling=False,
             deleted=False, permissions=("run.jobs.run", "run.jobs.runWithOverrides")):
    role = PROJECT + "/roles/overrides"
    item = {"name": JOB, "template": {"template": {"serviceAccount": _GSA,
            "containers": [{"image": "example.invalid/job:1",
                            **({"command": command} if command is not None else {})}]}},
            "terminalCondition": {"state": state}, "reconciling": reconciling,
            "iamPolicy": {"bindings": [{"role": role, "members": [SOURCE]}]},
            "_coverage": {"iamPolicy": {"status": "collected"}}}
    if deleted:
        item["deleteTime"] = "2026-01-01T00:00:00Z"
    model, target = _gcp_attached([
        ("iam_role", PROJECT, [{"name": role, "includedPermissions": list(permissions)}],
         "collected"),
        ("cloudrun_job", PROJECT, [item], "collected"),
    ])
    model = GcpModel(model.snapshot)
    return model.selector("gcp_run_job_override_path", True,
                          {target.id: model.principals[target.id]}, model.principals[SOURCE])


def test_recorded_interpreter_command_with_overridable_args():
    for command in (["/bin/sh"], ["python3", "-c"], ["/usr/bin/env", "python3"]):
        assert selected(command=command)["serviceAccount:" + _GSA][0] == "conditional"


def test_unknown_or_fixed_command_is_not_reported_as_code_execution():
    for command in (None, ["/usr/bin/curl"], ["/bin/sh", "-c", "fixed"]):
        assert selected(command=command)["serviceAccount:" + _GSA][0] == "unknown"


def test_job_state_and_exact_rights_gate_the_path():
    assert selected(command=["/bin/sh"], state="CONDITION_FAILED")[
        "serviceAccount:" + _GSA][0] == "unknown"
    assert selected(command=["/bin/sh"], reconciling=True)[
        "serviceAccount:" + _GSA][0] == "unknown"
    assert selected(command=["/bin/sh"], deleted=True) == {}
    assert selected(command=["/bin/sh"], permissions=("run.jobs.run",)) == {}
