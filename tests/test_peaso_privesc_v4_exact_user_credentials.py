"""Reviewed direct IAM-user credentials join to their exact readable AWS resource."""
from __future__ import annotations

import copy
import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import ACCOUNT, allow, aws_snap, reached, user


SOURCE = f"arn:aws:iam::{ACCOUNT}:user/alice"
TARGET = f"arn:aws:iam::{ACCOUNT}:user/victim"
OTHER = f"arn:aws:iam::{ACCOUNT}:user/other"
CASES = (
    ("aws-apprunner-plaintext-credential", "apprunner:DescribeService",
     f"arn:aws:apprunner:us-east-1:{ACCOUNT}:service/app/a1"),
    ("aws-lambda-getconfig-secret-identity", "lambda:GetFunctionConfiguration",
     f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:secrets"),
    ("aws-codebuild-plaintext-env-credential", "codebuild:BatchGetProjects",
     f"arn:aws:codebuild:us-east-1:{ACCOUNT}:project/secret-build"),
)


_CATALOG = {entry["id"]: {k: v for k, v in entry.items() if k != "_file"}
            for entry in privesc.load_catalog()["entries"]}


def _entry(tid):
    return copy.deepcopy(_CATALOG[tid])


def _fact(tid, action, resource):
    return {"TechniqueId": tid, "SourceArn": SOURCE, "TargetKind": "aws_user",
            "TargetId": TARGET, "TargetAccount": ACCOUNT,
            "CredentialKind": "aws_iam_user_access_key", "CredentialSubjectArn": TARGET,
            "CredentialResourceArn": resource, "AccessAction": action,
            "CredentialUsable": True, "EvidenceRef": "reviewed-fixture-1",
            "Status": "verified", "VerifiedPreconditions": True}


def _run(tid, action, resource, fact=None, permission_resource=None, permission_action=None):
    source = user("alice", allow(permission_action or action, permission_resource or resource))
    snap = aws_snap([source, user("victim"), user("other")])
    snap["collections"].append({"type": "aws_privesc_challenge_evidence",
                                "scope": f"{ACCOUNT}/us-east-1", "service": "privesc",
                                "status": "collected", "items": [fact] if isinstance(fact, dict) else fact or [],
                                "error": None})
    return privesc.analyze(snap, entries=[_entry(tid)])


@pytest.mark.parametrize("tid,action,resource", CASES)
def test_reviewed_usable_user_key_reaches_only_exact_subject(tid, action, resource):
    entry = _entry(tid)
    assert validate_entry(entry)[0] == []
    result = _run(tid, action, resource, _fact(tid, action, resource))
    assert reached(result, SOURCE, tid) == {TARGET: "conditional"}
    assert OTHER not in reached(result, SOURCE)
    assert all(f["status"] != "FAIL" for f in result["findings"])


@pytest.mark.parametrize("tid,action,resource", CASES)
def test_wrong_target_resource_or_effective_permission_cannot_reach(tid, action, resource):
    fact = _fact(tid, action, resource)
    for change in ({"CredentialSubjectArn": OTHER}, {"TargetId": OTHER},
                   {"CredentialResourceArn": resource.replace("us-east-1", "us-west-2")},
                   {"AccessAction": "iam:CreateUser"}, {"CredentialKind": "aws_sts_session"},
                   {"CredentialUsable": False}, {"Status": "disproven"},
                   {"SourceArn": OTHER}):
        altered = dict(fact, **change)
        result = _run(tid, action, resource, altered)
        assert TARGET not in reached(result, SOURCE, tid), (tid, change)
    wrong_resource = resource.replace("us-east-1", "us-west-2")
    result = _run(tid, action, resource, fact, permission_resource=wrong_resource)
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, action, resource, fact, permission_action="iam:CreateUser")
    assert TARGET not in reached(result, SOURCE, tid)


@pytest.mark.parametrize("tid,action,resource", CASES)
def test_conflicting_attestations_and_unverified_preconditions_cannot_reach(tid, action, resource):
    fact = _fact(tid, action, resource)
    conflict = dict(fact, Status="disproven")
    result = _run(tid, action, resource, [fact, conflict])
    assert TARGET not in reached(result, SOURCE, tid)
    result = _run(tid, action, resource, dict(fact, VerifiedPreconditions=False))
    assert TARGET not in reached(result, SOURCE, tid)


@pytest.mark.parametrize("tid,action,resource", CASES)
def test_missing_review_evidence_does_not_create_a_privesc_path(tid, action, resource):
    snap = aws_snap([user("alice", allow(action, resource)), user("victim")])
    for fact, status in ((None, None),
                         (dict(_fact(tid, action, resource), CredentialUsable=False), "collected"),
                         (_fact(tid, action, resource), "partial")):
        current = copy.deepcopy(snap)
        if fact is not None:
            current["collections"].append({"type": "aws_privesc_challenge_evidence",
                                           "scope": f"{ACCOUNT}/us-east-1", "service": "privesc",
                                           "status": status, "items": [fact], "error": None})
        result = privesc.analyze(current, entries=[_entry(tid)])
        assert not any(edge["source"] == SOURCE and tid in edge["techniques"]
                       for edge in result["graph"]["edges"])

