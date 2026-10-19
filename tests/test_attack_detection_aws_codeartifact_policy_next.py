"""CodeArtifact external package access requires matching accepted policy."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="external-package-grant", title="External package grant", level="medium",
    description="grant", technique_id="aws-codeartifact-external-repository-package-grant",
    product="aws", selection={"event.source": "codeartifact.amazonaws.com",
                              "event.name": "PutRepositoryPermissionsPolicy",
                              "event.outcome": "success",
                              "request.codeartifact_external_package_grant": True})


def _hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_external_read_and_negative_policy_variants() -> None:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::202533532952:root"},
        "Action": ["codeartifact:ReadFromRepository", "codeartifact:GetPackageVersionAsset"],
        "Resource": "*"}]}
    arn = "arn:aws:codeartifact:us-east-1:947247140022:repository/peasso-detect-ca95410751/test-repo"
    event = {"eventSource": "codeartifact.amazonaws.com",
             "eventName": "PutRepositoryPermissionsPolicy", "awsRegion": "us-east-1",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"domain": "peasso-detect-ca95410751", "repository": "test-repo",
                                   "policyDocument": json.dumps(policy)},
             "responseElements": {"policy": {"resourceArn": arn, "document": json.dumps(policy)}}}
    assert _hits(event) == [RULE.technique_id]
    for variant in ("same_account", "no_package_access", "conditional", "failed", "wrong_arn", "response_diff"):
        item = deepcopy(event)
        changed = deepcopy(policy)
        if variant == "same_account":
            changed["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::947247140022:root"
        if variant == "no_package_access":
            changed["Statement"][0]["Action"] = ["codeartifact:DescribeRepository"]
        if variant == "conditional":
            changed["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-canary"}}
        if variant in {"same_account", "no_package_access", "conditional"}:
            item["requestParameters"]["policyDocument"] = json.dumps(changed)
            item["responseElements"]["policy"]["document"] = json.dumps(changed)
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_arn": item["responseElements"]["policy"]["resourceArn"] = arn + "-other"
        if variant == "response_diff": item["responseElements"]["policy"]["document"] = "{}"
        assert _hits(item) == [], variant
