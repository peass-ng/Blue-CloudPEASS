"""Amplify role swaps need one usable app and correctly scoped branch grants."""

import json
from pathlib import Path

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col,
    edges, real, role, role_arn, user,
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


def test_customer_setup_grants_amplify_branch_inventory():
    template = json.loads((Path(__file__).resolve().parents[1] /
                           "infra/aws/customer-role.json").read_text())
    grants = [name for name, resource in template["Resources"].items()
              if resource.get("Type") == "AWS::IAM::ManagedPolicy"
              for statement in resource["Properties"]["PolicyDocument"]["Statement"]
              if "amplify:ListBranches" in (
                  statement["Action"] if isinstance(statement["Action"], list)
                  else [statement["Action"]])]
    assert grants == ["CspmConfigurationReadOnly6"]
