"""A Glue job change needs a concrete script both caller and role can use."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc import versioned_catalog as catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-glue-passrole-createjob-or-updatejob-run"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCRIPT = "arn:aws:s3:::glue-scripts/example.py"


def _case(*, script=SCRIPT, writer=SCRIPT, reader=SCRIPT, pass_service="glue.amazonaws.com",
          job_region="us-east-1", inventory="collected", encryption="absent"):
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
    snapshot["collections"].append({"type": "bucket", "scope": "111111111111/global",
        "service": "s3", "status": "collected", "error": None,
        "items": [{"Name": "glue-scripts", "Encryption":
                   {"collection_status": encryption} if encryption != "kms" else
                   {"collection_status": "collected", "ServerSideEncryptionConfiguration":
                    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}}]})
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_change_and_execution_bind_to_writable_role_readable_script():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_new_job_can_choose_a_different_script_and_kms_needs_more_evidence():
    alternate = "arn:aws:s3:::glue-scripts/alternate.py"
    assert _definite(_case(writer=alternate, reader=alternate)) == {TARGET: "conditional"}
    assert not _definite(_case(writer=alternate, reader=alternate, encryption="kms"))


def test_unrelated_script_or_wrong_passrole_does_not_reach_role():
    for kwargs in ({"writer": "arn:aws:s3:::other/example.py"},
                   {"reader": "arn:aws:s3:::other/example.py"},
                   {"pass_service": "lambda.amazonaws.com"},
                   {"inventory": "denied"}):
        assert not _definite(_case(**kwargs)), kwargs


def test_unverified_script_stays_unknown():
    result = privesc.analyze(_case(encryption="kms"), entries=[ENTRY], include_unknown=True)
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


def test_catalog_binding_preserves_prior_glue_wording():
    previous_binding = {"schema": catalog.BINDING_SCHEMA,
                        "manifest_sha256": catalog.GLUE_SCRIPT_690_PREVIOUS_MANIFEST,
                        "effective_tree_sha256": catalog.GLUE_SCRIPT_690_PREVIOUS_TREE,
                        "source_revision": catalog.V4_REVISION}
    previous, previous_status = catalog.lookup_entries([ID], previous_binding)
    current, current_status = catalog.lookup_entries([ID], catalog.current_binding())
    assert previous_status == "exact_previous_current"
    assert current_status == "exact_strict_privesc"
    assert "one recorded S3 script object" not in previous[ID]["notes"]
    assert "one concrete S3 script object" in current[ID]["notes"]
    assert "script may differ from existing job definitions" in current[ID]["notes"]


def test_existing_job_update_and_new_scheduled_trigger_also_bind():
    updated = _case()
    user = next(c for c in updated["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"][0] = {
        "Effect": "Allow", "Action": ["glue:UpdateJob", "glue:StartJobRun"],
        "Resource": "arn:aws:glue:us-east-1:111111111111:job/reference"}
    assert _definite(updated) == {TARGET: "conditional"}

    triggered = _case()
    user = next(c for c in triggered["collections"] if c["type"] == "iam_user")["items"][0]
    statements = user["UserPolicyList"][0]["PolicyDocument"]["Statement"]
    statements[0] = {"Effect": "Allow", "Action": "glue:CreateJob",
                     "Resource": "arn:aws:glue:us-east-1:111111111111:job/*"}
    statements.append({"Effect": "Allow", "Action": "glue:CreateTrigger",
                       "Resource": "arn:aws:glue:us-east-1:111111111111:trigger/*"})
    triggered["collections"].append({"type": "glue_trigger", "scope": "111111111111/us-east-1",
                                     "service": "glue", "status": "empty", "items": [], "error": None})
    assert _definite(triggered) == {TARGET: "conditional"}
