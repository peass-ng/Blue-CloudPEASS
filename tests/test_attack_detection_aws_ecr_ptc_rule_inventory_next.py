"""Synthetic derivative of an owned ECR CloudTrail inventory event."""

from copy import deepcopy

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"


def _rules(tmp_path):
    (tmp_path / "ecr.yml").write_text("""title: Synthetic ECR cache rule inventory
id: 18600000-0000-4000-8000-000000000099
status: experimental
description: Synthetic test rule.
references: [https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DescribePullThroughCacheRules.html]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: ecr.amazonaws.com
    event.name: DescribePullThroughCacheRules
    event.outcome: success
    request.ecr_pullthrough_cache_rules_listed: true
  condition: selection
falsepositives: [Approved ECR inventory]
level: low
x_hacktricks_technique_id: synthetic-ecr-ptc-rules-listed
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def _event():
    return {
        "eventSource": "ecr.amazonaws.com",
        "eventName": "DescribePullThroughCacheRules",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {"maxResults": 1}, "responseElements": None,
        "resources": [{"accountId": ACCOUNT, "ARN": "*"}],
    }


def test_observed_wildcard_resource_shape_matches_and_hashes_target(tmp_path):
    event = _event()
    hits = detect_aws_events([event], _rules(tmp_path))
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert "maxResults" not in str(hits)


def test_other_shapes_and_failed_inventory_are_negative(tmp_path):
    changes = [
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(eventSource="other.amazonaws.com"),
        lambda x: x.update(eventName="CreatePullThroughCacheRule"),
        lambda x: x.update(eventType="AwsServiceEvent"),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x.update(readOnly=False),
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x.update(awsRegion="invalid"),
        lambda x: x.update(requestParameters=None),
        lambda x: x.update(responseElements="invalid"),
        lambda x: x.update(resources=[]),
        lambda x: x["resources"][0].update(ARN="different"),
        lambda x: x["resources"][0].update(type="AWS::ECR::Repository"),
    ]
    events = []
    for change in changes:
        event = _event()
        change(event)
        events.append(event)
    assert detect_aws_events(events, _rules(tmp_path)) == []
