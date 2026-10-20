"""Synthetic coverage for six live-verified SageMaker CloudTrail shapes.

All account, organization and resource identifiers here are synthetic derivatives.
The real lab receipts remain private and are never imported by this test.
"""

from copy import deepcopy
import json

import pytest

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
GROUP = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:model-package-group/synthetic-group"


def event(name: str, params: dict, response: dict | None) -> dict:
    return {
        "eventName": name, "eventSource": "sagemaker.amazonaws.com",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "awsRegion": REGION,
        "recipientAccountId": ACCOUNT,
        "eventID": "11111111-1111-4111-8111-111111111111",
        "eventTime": "2026-10-20T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-actor/lab"},
        "requestParameters": params, "responseElements": response,
    }


CASES = [
    ("CreateNotebookInstance",
     {"NotebookInstanceName": "synthetic-notebook", "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-execution"},
     {"NotebookInstanceArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:notebook-instance/synthetic-notebook"},
     "request.sagemaker_notebook_role_passed"),
    ("CreatePresignedNotebookInstanceUrl", {"NotebookInstanceName": "synthetic-notebook"},
     {"AuthorizedUrl": "https://example.invalid/?token=synthetic"},
     "request.sagemaker_notebook_url_presigned"),
    ("UpdateNotebookInstanceLifecycleConfig",
     {"NotebookInstanceLifecycleConfigName": "synthetic-config", "OnStart": [{"Content": "c3ludGhldGlj"}]},
     None, "request.sagemaker_lifecycle_script_changed"),
    ("PutModelPackageGroupPolicy",
     {"ModelPackageGroupName": "synthetic-group", "ResourcePolicy": json.dumps({
         "Version": "2012-10-17", "Statement": [{"Sid": "SyntheticOrgDescribe", "Effect": "Allow",
             "Principal": "*", "Action": "sagemaker:DescribeModelPackageGroup", "Resource": GROUP,
             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}}]})},
     None, "request.sagemaker_model_group_org_wide_policy"),
    ("CreateModelPackage",
     {"ModelPackageGroupName": "synthetic-group", "ModelApprovalStatus": "Approved"},
     {"ModelPackageArn": f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:model-package/synthetic-group/1"},
     "request.sagemaker_model_package_approved"),
    ("DescribeModel", {"ModelName": "synthetic-model"},
     {"PrimaryContainer": {"Environment": {"SYNTHETIC": "synthetic"}}},
     "request.sagemaker_model_config_described"),
]


def rule(name: str, signal: str) -> Rule:
    return Rule(id="synthetic-" + name, title="Synthetic SageMaker route", level="medium",
                description="Synthetic dispatch check", technique_id="synthetic-route",
                product="aws", selection={"event.source": "sagemaker.amazonaws.com",
                                          "event.name": name, "event.outcome": "success", signal: True})


@pytest.mark.parametrize("name,params,response,signal", CASES)
def test_sagemaker_dispatch(name: str, params: dict, response: dict | None, signal: str) -> None:
    record = event(name, params, response)
    expected = rule(name, signal)
    found = detect_aws_events([record], [expected])
    assert len(found) == 1
    assert found[0].actor_id and found[0].target_id
    assert "AuthorizedUrl" not in str(found[0])
    assert "Environment" not in str(found[0])
    for change in ({"errorCode": "AccessDeniedException"}, {"eventSource": "wrong.amazonaws.com"}):
        denied = {**record, **change}
        assert detect_aws_events([denied], [expected]) == []


def test_sagemaker_org_policy_requires_org_condition_and_exact_group() -> None:
    name, params, response, signal = CASES[3]
    expected = rule(name, signal)
    for invalid in (
        {"Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "sagemaker:DescribeModelPackageGroup", "Resource": GROUP}]},
        {"Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "sagemaker:DescribeModelPackageGroup", "Resource": GROUP,
                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "bad"}}}]},
        {"Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "sagemaker:DescribeModelPackageGroup", "Resource": GROUP + "-other",
                        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1234567890"}}}]},
    ):
        altered = deepcopy(params)
        altered["ResourcePolicy"] = json.dumps(invalid)
        assert detect_aws_events([event(name, altered, response)], [expected]) == []
