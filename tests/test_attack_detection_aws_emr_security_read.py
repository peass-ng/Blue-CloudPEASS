"""Synthetic EMR security configuration read sequence tests."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection.aws_emr_security_read import correlate_aws_emr_security_reads
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
NAME = "synthetic-security-config"


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
        "requestParameters": {"name": NAME} if action == "DescribeSecurityConfiguration" else None,
        "responseElements": None,
    }


def rules(tmp_path):
    (tmp_path / "emr.yml").write_text("""title: Synthetic EMR configuration read
id: b3940000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/emr]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: elasticmapreduce.amazonaws.com
    event.name: EmrSecurityConfigurationReadAfterList
    event.outcome: success
    request.emr_security_configuration_read_after_list: true
  condition: selection
falsepositives: [Approved configuration review]
level: medium
x_hacktricks_technique_id: synthetic-emr-security-read
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_accepted_list_then_describe_correlates_without_name_or_response(tmp_path):
    records = [event("ListSecurityConfigurations", 0),
               event("DescribeSecurityConfiguration", 1)]
    hits = detect_aws_events(records, rules(tmp_path))
    assert [hit.technique_id for hit in hits] == ["synthetic-emr-security-read"]
    assert NAME not in str(hits)


def test_requires_list_before_named_read_same_actor_account_region_window():
    base = [event("ListSecurityConfigurations", 0),
            event("DescribeSecurityConfiguration", 1)]
    assert not correlate_aws_emr_security_reads([
        event("ListSecurityConfigurations", 2),
        event("DescribeSecurityConfiguration", 1),
    ])
    for change in (
        lambda e: e["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda e: e.update(recipientAccountId="111111111111"),
        lambda e: e.update(awsRegion="us-west-2"),
        lambda e: e.update(eventTime="2026-10-23T12:30:00Z"),
        lambda e: e["requestParameters"].update(name="bad name"),
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=False),
    ):
        variant = deepcopy(base)
        change(variant[1])
        assert not correlate_aws_emr_security_reads(variant)
    assert not correlate_aws_emr_security_reads(base[1:])
    assert not correlate_aws_emr_security_reads(base[:1])
