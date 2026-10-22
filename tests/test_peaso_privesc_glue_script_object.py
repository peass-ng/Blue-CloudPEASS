"""Bind a writable Glue script to the exact job and its execution role."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from peaso.privesc import schema
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc import versioned_catalog

from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, pol, role, user


SCOPE = f"{ACCOUNT}/us-east-1"
JOB = f"arn:aws:glue:us-east-1:{ACCOUNT}:job/report"
OBJECT = "arn:aws:s3:::scripts.example/report.py"
TARGET = f"arn:aws:iam::{ACCOUNT}:role/glue-exec"
ENTRY = next(row for row in schema.load_catalog(schema.CATALOG_DIR)["entries"]
             if row["id"] == "aws-glue-overwrite-existing-job-script")


def _model(*, put=OBJECT, start=JOB, read=OBJECT, script="s3://scripts.example/report.py",
           job_role=TARGET, job_status="collected", scheduled=False, fixed=(), defaults=(),
           trigger_override=False):
    actor = user("alice", {"Effect": "Allow", "Action": "s3:PutObject", "Resource": put},
                 {"Effect": "Allow", "Action": "glue:StartJobRun", "Resource": start} if start else
                 {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"})
    execution = role("glue-exec", pol({"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"},
                                       "Action": "sts:AssumeRole"}),
                     {"Effect": "Allow", "Action": "s3:GetObject", "Resource": read},
                     {"Effect": "Allow", "Action": "iam:CreateUser", "Resource": "*"})
    extra = [("glue_job", SCOPE, [{"Name": "report", "Role": job_role,
                                   "Command": {"Name": "pythonshell", "ScriptLocation": script},
                                   "DefaultCodeArguments": list(defaults),
                                   "NonOverridableCodeArguments": list(fixed)}], job_status)]
    if scheduled:
        extra.append(("glue_trigger", SCOPE, [{"Name": "nightly", "Type": "SCHEDULED",
                                                "State": "ACTIVATED", "HasSchedule": True,
                                                "ActionsComplete": True, "JobActions": ["report"],
                                                "ActionArgumentsComplete": True,
                                                "ScriptOverrideJobActions": ["report"] if trigger_override else []}],
                      "collected"))
    else:
        extra.append(("glue_trigger", SCOPE, [], "empty"))
    snap = aws_snap([actor], [execution], extra)
    return AwsModel(snap)


def _verdict(model):
    return model.precondition("glue_existing_job_script_object_writable_and_runnable",
                              {TARGET: model.principals[TARGET]}, model.principals[ALICE]).get(TARGET)


def test_exact_script_put_and_start_reaches_job_role():
    model = _model()
    assert _verdict(model) == ("conditional", "glue_exact_script_object_and_run_bound")
    edges = Evaluator(model, [ENTRY], include_unknown=False).run()
    assert {target for edge in edges if edge.source.id == ALICE for target in edge.targets} == {TARGET}


def test_active_schedule_can_run_exact_job_without_start_permission():
    assert _verdict(_model(start=None, scheduled=True)) == (
        "conditional", "glue_exact_script_object_and_run_bound")


def test_different_object_job_or_role_does_not_bind():
    for variant in ({"put": OBJECT + "-other"}, {"start": JOB + "-other"},
                    {"read": OBJECT + "-other"},
                    {"job_role": f"arn:aws:iam::{ACCOUNT}:role/other"}):
        assert _verdict(_model(**variant)) is None, variant


def test_missing_inventory_or_ambiguous_object_stays_unknown():
    assert _verdict(_model(job_status="denied"))[0] == "unknown"
    assert _verdict(_model(script="s3://scripts.example/report%2Epy"))[0] == "unknown"
    assert _verdict(_model(fixed=("--scriptLocation",)))[0] == "unknown"
    assert _verdict(_model(start=None, scheduled=True, defaults=("--scriptLocation",)))[0] == "unknown"
    assert _verdict(_model(start=None, scheduled=True, trigger_override=True))[0] == "unknown"


def test_direct_start_can_override_a_different_default_script():
    assert _verdict(_model(defaults=("--scriptLocation",))) == (
        "conditional", "glue_exact_script_object_and_run_bound")


def test_current_and_previous_catalog_bindings_are_exact():
    current = versioned_catalog.current_binding()
    entries, state = versioned_catalog.lookup_entries([ENTRY["id"]], current)
    assert state == "exact_strict_privesc" and ENTRY["id"] in entries
    old = dict(current,
               manifest_sha256=versioned_catalog.GLUE_SCRIPT_PREVIOUS_MANIFEST,
               effective_tree_sha256=versioned_catalog.GLUE_SCRIPT_PREVIOUS_TREE)
    entries, state = versioned_catalog.lookup_entries(
        [ENTRY["id"], "aws-glue-startjobrun-override-script"], old)
    assert state == "exact_previous_current"
    assert ENTRY["id"] not in entries and "aws-glue-startjobrun-override-script" in entries


def test_collector_keeps_argument_names_without_script_paths():
    path = Path.cwd() / "peaso/collectors/aws_facts_cb_ca.py"
    spec = spec_from_file_location("isolated_glue_flags", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    job = module._glue_job_flags(None, None, None, [{
        "Name": "report", "DefaultArguments": {"--scriptLocation": "s3://private/default.py"},
        "NonOverridableArguments": {"--extra-jars": "s3://private/dependency.jar"}}])[0]
    trigger = module._glue_trigger_names(None, None, None, [{
        "Name": "nightly", "Actions": [{"JobName": "report", "Arguments": {
            "--scriptLocation": "s3://private/trigger.py"}}]}])[0]
    assert job["DefaultCodeArguments"] == ["--scriptLocation"]
    assert job["NonOverridableCodeArguments"] == ["--extra-jars"]
    assert "DefaultArguments" not in job and "NonOverridableArguments" not in job
    assert trigger["ScriptOverrideJobActions"] == ["report"]
    assert trigger["ActionArgumentsComplete"] is True and "Actions" not in trigger
