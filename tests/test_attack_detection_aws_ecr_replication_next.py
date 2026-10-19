"""Cross-account registry replication is accepted and explicit."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="external-ecr-replication", title="External ECR replication", level="medium",
    description="replication", technique_id="aws-ecr-external-registry-replication", product="aws",
    selection={"event.source": "ecr.amazonaws.com", "event.name": "PutReplicationConfiguration",
               "event.outcome": "success", "request.ecr_external_replication": True},
)


def test_external_destination_and_cleanup_negative() -> None:
    config = {"rules": [{"destinations": [{"region": "us-west-2", "registryId": "947247140022"},
                                        {"region": "us-west-2", "registryId": "202533532952"}],
                         "repositoryFilters": [{"filter": "canary", "filterType": "PREFIX_MATCH"}]}]}
    event = {"eventSource": "ecr.amazonaws.com", "eventName": "PutReplicationConfiguration",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"replicationConfiguration": config},
             "responseElements": {"replicationConfiguration": deepcopy(config)}}
    assert [d.technique_id for d in detect_aws_events([event], [RULE])] == [RULE.technique_id]
    for variant in ("same_account", "cleared", "failed", "response_mismatch", "data_event"):
        item = deepcopy(event)
        if variant == "same_account":
            item["requestParameters"]["replicationConfiguration"]["rules"][0]["destinations"].pop()
            item["responseElements"] = deepcopy(item["requestParameters"])
        if variant == "cleared":
            item["requestParameters"]["replicationConfiguration"]["rules"] = []
            item["responseElements"] = deepcopy(item["requestParameters"])
        if variant == "failed":
            item["errorCode"] = "AccessDeniedException"
        if variant == "response_mismatch":
            item["responseElements"]["replicationConfiguration"]["rules"] = []
        if variant == "data_event":
            item["eventCategory"] = "Data"
        assert detect_aws_events([item], [RULE]) == [], variant
