"""Amplify role swaps need one usable app and correctly scoped branch grants."""

import json
from pathlib import Path

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col,
    edges, reached, real, role, role_arn, user,
)

APP = f"arn:aws:amplify:{REGION}:{ACCOUNT}:apps/d123"
BRANCH = APP + "/branches/main"
JOBS = BRANCH + "/jobs/*"
BUILD = "aws-amplify-updateapp-passrole"
SSR = "aws-amplify-updateapp-passrole-ssr"


def app(*, platform="WEB", repository=True, branch_status="collected",
        branch_role=None):
    branch = {"branchArn": BRANCH, "branchName": "main", "computeRoleArn": branch_role}
    return {"appId": "d123", "appArn": APP, "platform": platform,
            "RepositoryConnected": repository,
            "Branches": {"collection_status": branch_status, "items": [branch]}}


def result(ident, *, app_row=None, update=APP, start=JOBS, include_unknown=True):
    source = user("alice", allow("iam:PassRole", resource=role_arn("target")),
                  allow("amplify:UpdateApp", resource=update),
                  allow("amplify:StartJob", resource=start))
    return real(aws_snap([source], [role("target", "amplify.amazonaws.com")],
                         [col("amplify_app", [app_row or app()])]),
                ident, include_unknown=include_unknown)


def test_build_role_requires_same_app_branch_and_job_scope():
    assert_unresolved(result(BUILD), ALICE, BUILD)
    assert edges(result(BUILD, update=APP.replace("d123", "d999")), ALICE, BUILD) == []
    assert edges(result(BUILD, start=JOBS.replace("main", "other")), ALICE, BUILD) == []
    assert edges(result(BUILD, app_row=app(repository=False)), ALICE, BUILD) == []
    assert_unresolved(result(BUILD, app_row=app(branch_status="access_denied")), ALICE, BUILD)


def test_ssr_role_requires_ssr_app_and_no_other_branch_compute_role():
    assert_unresolved(result(SSR, app_row=app(platform="WEB_COMPUTE")), ALICE, SSR)
    assert edges(result(SSR), ALICE, SSR) == []
    assert edges(result(SSR, app_row=app(platform="WEB_COMPUTE",
                                        branch_role=role_arn("other"))), ALICE, SSR) == []
    assert edges(result(SSR, app_row=app(platform="WEB_COMPUTE"),
                        update=APP.replace("d123", "d999")), ALICE, SSR) == []


def test_amplify_role_routes_need_a_reviewed_useful_operation():
    object_arn = "arn:aws:s3:::private-bucket/evidence.txt"
    target = role("target", "amplify.amazonaws.com", allow("s3:PutObject", resource=object_arn))
    target["RoleId"] = "AROAAMPLIFY123456789"
    passed = allow("iam:PassRole", resource=target["Arn"])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "amplify.amazonaws.com"}}

    def run(ident, proof=None, *, extra_caller=(), branch_role=None, app_row=None):
        caller = user("alice", passed, allow("amplify:UpdateApp", resource=APP),
                      allow("amplify:StartJob", resource=JOBS), *extra_caller)
        proofs = proof if isinstance(proof, list) else ([proof] if proof else [])
        app_row = app_row or app(platform="WEB_COMPUTE" if ident == SSR else "WEB",
                                 branch_role=branch_role)
        snap = aws_snap([caller], [target], [col("amplify_app", [app_row]),
            col("aws_privesc_challenge_evidence", proofs)])
        snap["created_at"] = "2026-10-21T12:00:00+00:00"
        return real(snap, ident, include_unknown=True)

    for ident in (BUILD, SSR):
        proof = {"TechniqueId": ident, "SourceArn": ALICE, "TargetKind": "aws_role",
                 "TargetId": target["Arn"], "TargetRoleId": target["RoleId"],
                 "TargetScope": f"{ACCOUNT}/{REGION}", "AppArn": APP, "BranchArn": BRANCH,
                 "Status": "verified", "VerifiedPreconditions": True,
                 "ExecutionKind": "ssr" if ident == SSR else "build",
                 "RoleAssociationConfirmed": True, "EffectUsefulToSource": True,
                 "RoleAction": "s3:PutObject", "RoleResource": object_arn,
                 "EffectiveBuildCommandsControlledBySource": True,
                 "BuildJobSucceeded": True, "RoleOperationObservedInBuild": True,
                 "JobArn": BRANCH + "/jobs/1",
                 "DeployedSsrCodeControlledBySource": True,
                 "HttpRequestReachedSsrRoute": True,
                 "SsrRoleOperationSucceeded": True, "RequestPath": "/api/use-role",
                 "EvidenceRef": "reviewed-amplify-operation",
                 "EvidenceObservedAt": "2026-10-21T11:59:00+00:00",
                 "EvidenceExpiresAt": "2026-10-21T12:05:00+00:00"}
        assert target["Arn"] in reached(run(ident, proof), ALICE, ident)
        assert target["Arn"] not in reached(run(ident), ALICE, ident)
        assert_unresolved(run(ident), ALICE, ident)
        assert target["Arn"] not in reached(run(ident, [proof, dict(proof)]), ALICE, ident)
        for changed in ({"TargetRoleId": "AROADIFFERENT"}, {"BranchArn": APP + "/branches/other"},
                        {"RoleAssociationConfirmed": False}, {"RoleAction": "s3:DeleteObject"},
                        {"EffectUsefulToSource": False},
                        {"SourceArn": f"arn:aws:iam::{ACCOUNT}:user/other"},
                        {"EvidenceObservedAt": "2026-10-21T11:40:00+00:00"}):
            assert target["Arn"] not in reached(run(ident, dict(proof, **changed)), ALICE, ident)
        if ident == BUILD:
            for changed in ({"EffectiveBuildCommandsControlledBySource": False},
                            {"BuildJobSucceeded": False}, {"RoleOperationObservedInBuild": False},
                            {"JobArn": APP + "/branches/other/jobs/1"}):
                assert target["Arn"] not in reached(run(ident, dict(proof, **changed)), ALICE, ident)
        else:
            for changed in ({"DeployedSsrCodeControlledBySource": False},
                            {"HttpRequestReachedSsrRoute": False},
                            {"SsrRoleOperationSucceeded": False}):
                assert target["Arn"] not in reached(run(ident, dict(proof, **changed)), ALICE, ident)
            assert target["Arn"] not in reached(run(ident, proof, branch_role=role_arn("other")),
                                                ALICE, ident)
        assert target["Arn"] not in reached(run(ident, proof,
            extra_caller=[allow("s3:PutObject", resource=object_arn)]), ALICE, ident)
        second_branch = APP + "/branches/feature"
        two_branches = app(platform="WEB_COMPUTE" if ident == SSR else "WEB")
        two_branches["Branches"]["items"].append({"branchArn": second_branch,
                                                   "branchName": "feature", "computeRoleArn": None})
        later_proof = dict(proof, BranchArn=second_branch, JobArn=second_branch + "/jobs/1")
        extra = [allow("amplify:StartJob", resource=second_branch + "/jobs/*")] if ident == BUILD else []
        assert target["Arn"] in reached(run(ident, later_proof, app_row=two_branches,
                                             extra_caller=extra), ALICE, ident)


def test_customer_setup_grants_amplify_branch_inventory():
    template = json.loads((Path(__file__).resolve().parents[1] /
                           "infra/aws/customer-role.json").read_text())
    grants = [name for name, resource in template["Resources"].items()
              if resource.get("Type") == "AWS::IAM::ManagedPolicy"
              for statement in resource["Properties"]["PolicyDocument"]["Statement"]
              if "amplify:ListBranches" in (
                  statement["Action"] if isinstance(statement["Action"], list)
                  else [statement["Action"]])]
    assert len(grants) == 1
    assert grants[0].startswith("CspmConfigurationReadOnly")
