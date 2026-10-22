"""Changing an existing Glue job needs a runnable trigger and usable script."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-glue-updatejob-existing-role"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCRIPT = "arn:aws:s3:::glue-scripts/example.py"
JOB = "arn:aws:glue:us-east-1:111111111111:job/job1"


def _case(*, writer=SCRIPT, reader=SCRIPT, service="glue.amazonaws.com",
          job_resource=JOB, trigger_state="ACTIVATED"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "glue:UpdateJob", "Resource": job_resource},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": service}}},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": writer}]
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["RolePolicyList"] = [{"PolicyName": "read", "PolicyDocument": {"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": reader}]}}]
    snapshot["collections"].extend([
        {"type": "glue_job", "scope": "111111111111/us-east-1", "service": "glue",
         "status": "collected", "error": None, "items": [{"Name": "job1", "Role": TARGET,
         "Command": {"Name": "glueetl", "ScriptLocation": "s3://glue-scripts/example.py"}}]},
        {"type": "glue_trigger", "scope": "111111111111/us-east-1", "service": "glue",
         "status": "collected", "error": None, "items": [{"Name": "daily", "Type": "SCHEDULED",
         "State": trigger_state, "HasSchedule": True, "ActionsComplete": True,
         "JobActions": ["job1"]}]},
    ])
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_update_job_joins_role_trigger_and_script():
    assert _definite(_case()) == {TARGET: "conditional"}
    for kwargs in ({"writer": "arn:aws:s3:::other/example.py"},
                   {"reader": "arn:aws:s3:::other/example.py"},
                   {"service": "lambda.amazonaws.com"},
                   {"job_resource": "arn:aws:glue:us-east-1:111111111111:job/other"},
                   {"trigger_state": "CREATED"}):
        assert not _definite(_case(**kwargs)), kwargs


def test_unverified_script_is_unknown():
    members = reached(privesc.analyze(_case(reader="arn:aws:s3:::other/example.py"),
                                      entries=[ENTRY], include_unknown=True), SOURCE, ID)
    assert TARGET not in members
    assert any(name.startswith("unresolved:") and confidence == "unknown"
               for name, confidence in members.items())
