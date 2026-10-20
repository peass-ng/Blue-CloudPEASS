"""Synthetic dispatch checks for the three live-verified AWS route batches."""

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "111111111111"
POLICY = f"arn:aws:iam::{ACCOUNT}:policy/synthetic-policy"
BUILD_ID = "synthetic:11111111-1111-4111-8111-111111111111"
NEW_BUILD_ID = "synthetic:22222222-2222-4222-8222-222222222222"


IAM_REMOVAL = [
    ("DeleteGroupPolicy", {"groupName": "synthetic-group", "policyName": "synthetic-deny"}),
    ("DeleteRolePolicy", {"roleName": "synthetic-role", "policyName": "synthetic-deny"}),
    ("DeleteUserPolicy", {"userName": "synthetic-user", "policyName": "synthetic-deny"}),
    ("DetachGroupPolicy", {"groupName": "synthetic-group", "policyArn": POLICY}),
    ("DetachRolePolicy", {"roleName": "synthetic-role", "policyArn": POLICY}),
    ("DetachUserPolicy", {"userName": "synthetic-user", "policyArn": POLICY}),
    ("DeletePolicyVersion", {"policyArn": POLICY, "versionId": "v2"}),
    ("DeletePolicy", {"policyArn": POLICY}),
]
IAM_CREDENTIAL = [
    ("SetDefaultPolicyVersion", {"policyArn": POLICY, "versionId": "v2"}),
    ("CreateAccessKey", {"userName": "synthetic-user"}),
    ("DeleteAccessKey", {"userName": "synthetic-user", "accessKeyId": "AKIA" + "A" * 16}),
    ("CreateServiceSpecificCredential", {"userName": "synthetic-user", "serviceName": "codecommit.amazonaws.com"}),
    ("ResetServiceSpecificCredential", {"userName": "synthetic-user", "serviceSpecificCredentialId": "A" * 16}),
    ("PutUserPermissionsBoundary", {"userName": "synthetic-user", "permissionsBoundary": POLICY}),
    ("PutRolePermissionsBoundary", {"roleName": "synthetic-role", "permissionsBoundary": POLICY}),
    ("UpdateUser", {"userName": "synthetic-user", "newUserName": "synthetic-user", "newPath": "/lab/controlled/"}),
    ("UpdateGroup", {"groupName": "synthetic-group", "newGroupName": "synthetic-group", "newPath": "/lab/controlled/"}),
]
CODEBUILD = [
    ("StartBuild", {"projectName": "synthetic", "buildspecOverride": "version: 0.2"},
     "request.codebuild_buildspec_override_present", {"build": {"id": BUILD_ID}}),
    ("StartBuild", {"projectName": "synthetic", "environmentVariablesOverride": [
        {"name": "SYNTHETIC", "value": "marker", "type": "PLAINTEXT"}]},
     "request.codebuild_environment_override_present", {"build": {"id": BUILD_ID}}),
    ("RetryBuild", {"id": BUILD_ID}, "request.codebuild_retry", {"build": {"id": NEW_BUILD_ID}}),
    ("UpdateProject", {"name": "synthetic", "source": {"type": "NO_SOURCE"}},
     "request.codebuild_project_definition_supplied", {"project": {"name": "synthetic"}}),
    ("UpdateProject", {"name": "synthetic", "serviceRole": f"arn:aws:iam::{ACCOUNT}:role/synthetic"},
     "request.codebuild_service_role_supplied", {"project": {"name": "synthetic"}}),
]


def event(source: str, action: str, request: dict, response: dict | None = None) -> dict:
    return {
        "eventSource": source, "eventName": action, "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
        "eventID": "33333333-3333-4333-8333-333333333333",
        "eventTime": "2026-10-20T00:00:00Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic/lab"},
        "requestParameters": request, "responseElements": response,
    }


@pytest.mark.parametrize("action,params", IAM_REMOVAL)
def test_policy_removal_dispatch(action: str, params: dict) -> None:
    check("iam.amazonaws.com", action, params, "request.iam_policy_removal_observed")


@pytest.mark.parametrize("action,params", IAM_CREDENTIAL)
def test_iam_credential_boundary_dispatch(action: str, params: dict) -> None:
    check("iam.amazonaws.com", action, params,
          "request.iam_credential_boundary_action_observed")


@pytest.mark.parametrize("action,params,selector,response", CODEBUILD)
def test_codebuild_execution_dispatch(action: str, params: dict, selector: str,
                                      response: dict) -> None:
    check("codebuild.amazonaws.com", action, params, selector, response)


def check(source: str, action: str, request: dict, selector: str,
          response: dict | None = None) -> None:
    rule = Rule(id=f"synthetic-{source}-{action}-{selector}", title="Synthetic route",
                level="medium", description="Synthetic dispatch check",
                technique_id="synthetic-route", product="aws",
                selection={"event.source": source, "event.name": action,
                           "event.outcome": "success", selector: True})
    row = event(source, action, request, response)
    positive = detect_aws_events([row], [rule])
    assert len(positive) == 1
    assert positive[0].actor_id and positive[0].target_id
    denied = deepcopy(row)
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied], [rule]) == []
    wrong_source = deepcopy(row)
    wrong_source["eventSource"] = "wrong.amazonaws.com"
    assert detect_aws_events([wrong_source], [rule]) == []
