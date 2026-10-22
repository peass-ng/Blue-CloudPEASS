"""Synthetic derivatives of accepted EMR termination management events."""

from copy import deepcopy

from peaso.attack_detection.aws_emr_termination import normalize_aws_emr_termination
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
CLUSTER = "j-ABCDEFGH12345678"


def event() -> dict:
    return {
        "eventSource": "elasticmapreduce.amazonaws.com",
        "eventName": "TerminateJobFlows", "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
        "eventID": "synthetic-termination", "eventTime": "2026-10-23T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"jobFlowIds": [CLUSTER]},
        "responseElements": None,
    }


def rules(tmp_path):
    (tmp_path / "emr.yml").write_text("""title: Synthetic EMR termination
id: b3970000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: elasticmapreduce.amazonaws.com
    event.name: TerminateJobFlows
    event.outcome: success
    request.emr_clusters_termination_requested: true
  condition: selection
falsepositives: [Approved shutdown]
level: medium
x_hacktricks_technique_id: synthetic-emr-termination
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_accepted_request_matches_without_exposing_cluster_id(tmp_path):
    hits = detect_aws_events([event()], rules(tmp_path))
    assert [hit.technique_id for hit in hits] == ["synthetic-emr-termination"]
    assert CLUSTER not in str(hits)


def test_failure_or_malformed_ids_do_not_match():
    base = event()
    for change in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=True),
        lambda e: e.update(managementEvent=False),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e.update(eventType="AwsServiceEvent"),
        lambda e: e["userIdentity"].update(accountId="111111111111"),
        lambda e: e["requestParameters"].update(jobFlowIds=[]),
        lambda e: e["requestParameters"].update(jobFlowIds=["invalid"]),
        lambda e: e.update(eventID=""),
    ):
        variant = deepcopy(base)
        change(variant)
        assert normalize_aws_emr_termination(variant) is None
