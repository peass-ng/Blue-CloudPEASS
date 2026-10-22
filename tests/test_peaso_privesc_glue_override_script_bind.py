"""Starting a Glue job with a script override needs a controlled readable object."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-glue-startjobrun-override-script"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCRIPT = "arn:aws:s3:::glue-scripts/example.py"
JOB = "arn:aws:glue:us-east-1:111111111111:job/victim-job"


def _case(*, writer=SCRIPT, reader=SCRIPT, fixed=(), job_resource=JOB, inventory="collected"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "glue:StartJobRun", "Resource": job_resource},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": writer}]
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["RolePolicyList"] = [{"PolicyName": "read", "PolicyDocument": {"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": reader}]}}]
    snapshot["collections"].append({"type": "glue_job", "scope": "111111111111/us-east-1",
        "service": "glue", "status": inventory, "error": None,
        "items": [{"Name": "victim-job", "Role": TARGET,
                   "Command": {"Name": "glueetl", "ScriptLocation": "s3://glue-scripts/example.py"},
                   "NonOverridableCodeArguments": list(fixed)}] if inventory == "collected" else []})
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_override_needs_one_writable_and_role_readable_script():
    assert _definite(_case()) == {TARGET: "conditional"}
    for kwargs in ({"writer": "arn:aws:s3:::elsewhere/example.py"},
                   {"reader": "arn:aws:s3:::elsewhere/example.py"},
                   {"fixed": ("--scriptLocation",)},
                   {"job_resource": "arn:aws:glue:us-east-1:111111111111:job/elsewhere"},
                   {"inventory": "denied"}):
        assert not _definite(_case(**kwargs)), kwargs


def test_missing_script_witness_is_unknown():
    members = reached(privesc.analyze(_case(writer="arn:aws:s3:::elsewhere/example.py"),
                                      entries=[ENTRY], include_unknown=True), SOURCE, ID)
    assert TARGET not in members
    assert any(name.startswith("unresolved:") and confidence == "unknown"
               for name, confidence in members.items())
