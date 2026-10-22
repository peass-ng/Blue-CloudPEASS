"""Synthetic derivatives of EMR cluster inventory management events."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection.aws_emr_inventory import correlate_aws_emr_inventory
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
CLUSTER = "j-ABCDEFGH12345678"
ACTIONS = ("DescribeCluster", "ListInstances", "ListBootstrapActions")


def event(action: str, minute: int) -> dict:
    stamp = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return {
        "eventSource": "elasticmapreduce.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"synthetic-{minute}-{action}",
        "eventTime": stamp.isoformat().replace("+00:00", "Z"),
        "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
        "requestParameters": {"clusterId": CLUSTER},
        "responseElements": None,
    }


def sweep() -> list[dict]:
    return [event(action, minute) for minute, action in enumerate(ACTIONS)]


def rules(tmp_path):
    (tmp_path / "emr.yml").write_text("""title: Synthetic EMR inventory sweep
id: b3930000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: elasticmapreduce.amazonaws.com
    event.name: EmrClusterInventorySweep
    event.outcome: success
    request.emr_cluster_inventory_sweep: true
  condition: selection
falsepositives: [Approved inventory sweep]
level: medium
x_hacktricks_technique_id: synthetic-emr-inventory-sweep
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_three_accepted_reads_correlate_without_response_data(tmp_path):
    hits = detect_aws_events(list(reversed(sweep())), rules(tmp_path))
    assert [hit.technique_id for hit in hits] == ["synthetic-emr-inventory-sweep"]
    assert hits[0].target_id.startswith("sha256:")
    assert CLUSTER not in str(hits)


def test_requires_three_distinct_actions_same_actor_region_account_cluster_window():
    base = sweep()
    for index in range(3):
        assert not correlate_aws_emr_inventory(base[:index] + base[index + 1:])
    for change in (
        lambda e: e["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda e: e.update(recipientAccountId="111111111111"),
        lambda e: e.update(awsRegion="us-west-2"),
        lambda e: e["requestParameters"].update(clusterId="j-OTHER1234567890"),
        lambda e: e.update(eventTime="2026-10-23T12:30:00Z"),
    ):
        variant = deepcopy(base)
        change(variant[-1])
        assert not correlate_aws_emr_inventory(variant)


def test_failure_or_malformed_read_does_not_correlate():
    base = sweep()
    for change in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=False),
        lambda e: e.update(managementEvent=False),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e.update(eventType="AwsServiceEvent"),
        lambda e: e.update(eventID=""),
        lambda e: e["userIdentity"].update(accountId="111111111111"),
        lambda e: e["requestParameters"].update(clusterId="invalid"),
    ):
        variant = deepcopy(base)
        change(variant[-1])
        assert not correlate_aws_emr_inventory(variant)


def test_repeated_read_does_not_replace_missing_action():
    base = sweep()
    base[-1] = event("DescribeCluster", 2)
    assert not correlate_aws_emr_inventory(base)
