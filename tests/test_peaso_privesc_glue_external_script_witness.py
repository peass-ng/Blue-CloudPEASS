"""Glue job paths can use a controlled script outside the recorded job scripts."""
from __future__ import annotations

from peaso import privesc
from tests import test_peaso_privesc_glue_job_script_bind as create
from tests import test_peaso_privesc_glue_override_script_bind as override
from tests import test_peaso_privesc_glue_updatejob_script_bind as update
from tests.test_peaso_privesc_schema_ext import reached

SCRIPT = "s3://glue-scripts/new.py"
OBJECT = "arn:aws:s3:::glue-scripts/new.py"
EFFECT = "arn:aws:s3:::private-bucket/report"
TRIGGER = "arn:aws:glue:us-east-1:111111111111:trigger/verified"


def add_proof(snap, technique, job, route, change=None, *, wrong_role=False):
    source = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    role = next(c for c in snap["collections"] if c["type"] == "iam_role")["items"][0]
    role["RoleId"] = "AROA-GLUE"
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": OBJECT})
    role["RolePolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJECT})
    role["RolePolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "s3:PutObject", "Resource": EFFECT})
    proof = {
        "TechniqueId": technique, "SourceArn": create.SOURCE, "TargetKind": "aws_role",
        "TargetId": create.TARGET, "JobRoleArn": create.TARGET,
        "TargetRoleId": "AROA-WRONG" if wrong_role else "AROA-GLUE",
        "Status": "verified", "VerifiedPreconditions": True,
        "EvidenceRef": "evidence://glue/external-script",
        "EvidenceObservedAt": "2026-10-22T12:00:00Z", "EvidenceExpiresAt": "2026-10-22T12:10:00Z",
        "JobArn": job, "ScriptS3Uri": SCRIPT, "ExecutionRoute": route,
        "ScriptObjectControlled": True, "ScriptReadSucceeded": True,
        "JobRunSucceeded": True, "ScriptExecuted": True,
        "CodeUsedJobRoleCredentials": True, "RoleAction": "s3:PutObject",
        "RoleActionResource": EFFECT, "RoleActionSucceeded": True,
        "EffectUsefulToSource": True,
    }
    if change:
        proof["JobChangeAction"] = change
        proof["JobChangeSucceeded"] = True
    if route != "StartJobRun":
        proof["TriggerArn"] = TRIGGER
        proof["TriggerFired"] = True
    snap["created_at"] = "2026-10-22T12:01:00Z"
    collection = next(c for c in snap["collections"]
                      if c["type"] == "aws_privesc_challenge_evidence")
    collection["items"] = [proof]
    return snap


def test_new_job_uses_external_script_witness():
    snap = create._case(writer=OBJECT, reader=OBJECT)
    add_proof(snap, create.ID, "arn:aws:glue:us-east-1:111111111111:job/new-job",
              "StartJobRun", "CreateJob")
    result = privesc.analyze(snap, entries=[create.ENTRY])
    assert reached(result, create.SOURCE, create.ID) == {create.TARGET: "conditional"}


def test_override_uses_external_script_witness():
    # KMS leaves the native script route unresolved, isolating the verified execution proof.
    snap = override._case(writer=OBJECT, reader=OBJECT, encryption="kms")
    add_proof(snap, override.ID, override.JOB, "StartJobRun")
    result = privesc.analyze(snap, entries=[override.ENTRY])
    assert reached(result, override.SOURCE, override.ID) == {override.TARGET: "conditional"}


def test_update_uses_external_script_witness():
    snap = update._case(writer=OBJECT, reader=OBJECT)
    add_proof(snap, update.ID, update.JOB, "ExistingTrigger", "UpdateJob")
    result = privesc.analyze(snap, entries=[update.ENTRY])
    assert reached(result, update.SOURCE, update.ID) == {update.TARGET: "conditional"}


def test_external_script_wrong_role_id_does_not_override_native_route():
    native = override._case(writer=OBJECT, reader=OBJECT)
    native_result = privesc.analyze(native, entries=[override.ENTRY], include_unknown=True)
    native_reaches = reached(native_result, override.SOURCE, override.ID)
    assert native_reaches == {override.TARGET: "conditional"}

    snap = override._case(writer=OBJECT, reader=OBJECT)
    add_proof(snap, override.ID, override.JOB, "StartJobRun", wrong_role=True)
    result = privesc.analyze(snap, entries=[override.ENTRY], include_unknown=True)
    assert reached(result, override.SOURCE, override.ID) == native_reaches

    # KMS leaves the independent native route unresolved, exposing the proof mismatch.
    isolated = override._case(writer=OBJECT, reader=OBJECT, encryption="kms")
    add_proof(isolated, override.ID, override.JOB, "StartJobRun", wrong_role=True)
    isolated_result = privesc.analyze(isolated, entries=[override.ENTRY], include_unknown=True)
    assert override.TARGET not in reached(isolated_result, override.SOURCE, override.ID)
