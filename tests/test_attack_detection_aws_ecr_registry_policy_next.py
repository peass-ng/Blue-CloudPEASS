"""ECR registry replication policy requires a matching accepted document."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="registry-replication-grant", title="External registry replication grant", level="medium",
    description="replication grant", technique_id="aws-ecr-external-replication-registry-grant",
    product="aws", selection={"event.source": "ecr.amazonaws.com",
                              "event.name": "PutRegistryPolicy", "event.outcome": "success",
                              "request.ecr_external_replication_registry_grant": True},
)


def test_external_replication_grant_and_rejected_variants() -> None:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::202533532952:root"},
        "Action": ["ecr:ReplicateImage", "ecr:CreateRepository"],
        "Resource": ["arn:aws:ecr:us-east-1:947247140022:repository/canary/*"]}]}
    event = {"eventSource": "ecr.amazonaws.com", "eventName": "PutRegistryPolicy",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"policyText": json.dumps(policy)},
             "responseElements": {"registryId": "947247140022", "policyText": json.dumps(policy)}}
    assert [x.technique_id for x in detect_aws_events([event], [RULE])] == [RULE.technique_id]
    canonicalized = deepcopy(event)
    normalized = deepcopy(policy)
    normalized["Statement"][0]["Resource"] = normalized["Statement"][0]["Resource"][0]
    canonicalized["responseElements"]["policyText"] = json.dumps(normalized)
    assert [x.technique_id for x in detect_aws_events([canonicalized], [RULE])] == [RULE.technique_id]
    for variant in ("same_account", "no_replication", "conditional", "failed", "mismatch", "data_event"):
        item = deepcopy(event)
        document = deepcopy(policy)
        if variant == "same_account":
            document["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::947247140022:root"
        if variant == "no_replication": document["Statement"][0]["Action"] = ["ecr:DescribeRepositories"]
        if variant == "conditional":
            document["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-canary"}}
        if variant in {"same_account", "no_replication", "conditional"}:
            item["requestParameters"]["policyText"] = json.dumps(document)
            item["responseElements"]["policyText"] = json.dumps(document)
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "mismatch": item["responseElements"]["policyText"] = "{}"
        if variant == "data_event": item["eventCategory"] = "Data"
        assert detect_aws_events([item], [RULE]) == [], variant
