"""A Glue job change needs a concrete script both caller and role can use."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-glue-passrole-createjob-or-updatejob-run"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCRIPT = "arn:aws:s3:::glue-scripts/example.py"


def _case(*, script=SCRIPT, writer=SCRIPT, reader=SCRIPT, pass_service="glue.amazonaws.com",
          job_region="us-east-1", inventory="collected"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": ["glue:CreateJob", "glue:StartJobRun"], "Resource": "*"},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": pass_service}}},
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": writer},
    ]
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"] = {"Statement": [
        {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    role["RolePolicyList"] = [{"PolicyName": "read", "PolicyDocument": {"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": reader}]}}]
    snapshot["collections"].append({"type": "glue_job", "scope": f"111111111111/{job_region}",
        "service": "glue", "status": inventory, "error": None,
        "items": [{"Name": "reference", "Command": {"Name": "glueetl",
                   "ScriptLocation": "s3://" + script.split(":::", 1)[1]}}] if inventory == "collected" else []})
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_change_and_execution_bind_to_writable_role_readable_script():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_unrelated_script_or_wrong_passrole_does_not_reach_role():
    for kwargs in ({"writer": "arn:aws:s3:::other/example.py"},
                   {"reader": "arn:aws:s3:::other/example.py"},
                   {"pass_service": "lambda.amazonaws.com"},
                   {"inventory": "empty"},
                   {"inventory": "denied"}):
        assert not _definite(_case(**kwargs)), kwargs


def test_unverified_script_stays_unknown():
    result = privesc.analyze(_case(inventory="empty"), entries=[ENTRY], include_unknown=True)
    members = reached(result, SOURCE, ID)
    assert TARGET not in members
    assert any(member.startswith("unresolved:") and confidence == "unknown"
               for member, confidence in members.items())


def test_script_witness_can_be_in_another_region():
    snapshot = _case(job_region="us-west-2")
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = (
        "arn:aws:glue:us-east-1:111111111111:job/*")
    snapshot["collections"].append({"type": "glue_job", "scope": "111111111111/us-east-1",
                                    "service": "glue", "status": "empty", "items": [], "error": None})
    assert _definite(snapshot) == {TARGET: "conditional"}
