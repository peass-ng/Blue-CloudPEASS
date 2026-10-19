"""Live-shaped ECR template and Secrets Manager policy decisions."""

from __future__ import annotations

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


TEMPLATE = Rule(
    id="template-grant", title="Template wildcard read", level="high", description="grant",
    technique_id="aws-ecr-template-wildcard-image-read", product="aws",
    selection={"event.source": "ecr.amazonaws.com",
               "event.name": ["CreateRepositoryCreationTemplate", "UpdateRepositoryCreationTemplate"],
               "event.outcome": "success", "request.ecr_template_wildcard_read_grant": True},
)
SECRET = Rule(
    id="secret-self-grant", title="Secret self read", level="high", description="grant",
    technique_id="aws-secretsmanager-self-read-policy", product="aws",
    selection={"event.source": "secretsmanager.amazonaws.com", "event.name": "PutResourcePolicy",
               "event.outcome": "success", "request.secretsmanager_self_read_grant": True},
)


def _event(source: str, name: str, request: dict, response: dict) -> dict:
    return {
        "eventSource": source, "eventName": name, "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "eventID": "a3daf387-f9c2-4131-96bf-eda69ded3a5c",
        "eventTime": "2026-10-19T09:08:21Z", "awsRegion": "us-east-1",
        "recipientAccountId": "947247140022",
        "userIdentity": {"type": "IAMUser", "accountId": "947247140022",
                         "arn": "arn:aws:iam::947247140022:user/testenv"},
        "requestParameters": request, "responseElements": response,
    }


def _hits(row: dict) -> list[str]:
    return [m.technique_id for m in detect_aws_events([row], [TEMPLATE, SECRET])]


def test_ecr_template_update_and_benign_creation() -> None:
    prefix = "peasso-detect-template-da49ec8f44"
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]}]}
    row = _event("ecr.amazonaws.com", "UpdateRepositoryCreationTemplate",
                 {"prefix": prefix, "repositoryPolicy": json.dumps(policy)},
                 {"registryId": "947247140022", "repositoryCreationTemplate": {
                     "prefix": prefix, "repositoryPolicy": json.dumps(policy)}})
    assert _hits(row) == [TEMPLATE.technique_id]
    benign = deepcopy(row)
    benign["eventName"] = "CreateRepositoryCreationTemplate"
    benign["requestParameters"].pop("repositoryPolicy")
    benign["responseElements"]["repositoryCreationTemplate"].pop("repositoryPolicy")
    assert _hits(benign) == []
    for edit in ("conditional", "narrow_principal", "missing_response", "denied"):
        item = deepcopy(row)
        p = deepcopy(policy)
        if edit == "conditional": p["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-x"}}
        if edit == "narrow_principal": p["Statement"][0]["Principal"] = "arn:aws:iam::111122223333:root"
        if edit == "missing_response": item["responseElements"] = {}
        if edit == "denied": item["errorCode"] = "AccessDeniedException"
        item["requestParameters"]["repositoryPolicy"] = json.dumps(p)
        assert _hits(item) == [], edit


def test_secret_self_read_and_describe_only() -> None:
    arn = "arn:aws:secretsmanager:us-east-1:947247140022:secret:peasso-detect-self-secret-8977f76e50-qlvM1z"
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
              "Principal": {"AWS": "arn:aws:iam::947247140022:user/testenv"},
              "Action": "secretsmanager:GetSecretValue", "Resource": arn}]}
    row = _event("secretsmanager.amazonaws.com", "PutResourcePolicy",
                 {"secretId": arn, "resourcePolicy": json.dumps(policy), "blockPublicPolicy": True},
                 {"name": "peasso-detect-self-secret-8977f76e50", "arn": arn})
    assert _hits(row) == [SECRET.technique_id]
    for edit in ("describe_only", "other_principal", "conditional", "wrong_secret", "denied"):
        item = deepcopy(row)
        p = deepcopy(policy)
        if edit == "describe_only": p["Statement"][0]["Action"] = "secretsmanager:DescribeSecret"
        if edit == "other_principal": p["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::947247140022:user/other"
        if edit == "conditional": p["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalTag/team": "backup"}}
        if edit == "wrong_secret": item["responseElements"]["arn"] = arn.replace("qlvM1z", "000000")
        if edit == "denied": item["errorCode"] = "AccessDeniedException"
        item["requestParameters"]["resourcePolicy"] = json.dumps(p)
        assert _hits(item) == [], edit
