"""Only an accepted table setting change creates the timestamp signal."""

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.aws_keyspaces_timestamps_next import normalize
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
KEYSPACE = "synthetic"
TABLE = "records"
ARN = f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/{KEYSPACE}/table/{TABLE}"


def event():
    return {
        "eventSource": "cassandra.amazonaws.com", "eventName": "AlterTable",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {
            "keyspaceName": KEYSPACE, "tableName": TABLE,
            "rawquery": (
                'ALTER TABLE "synthetic"."records" WITH CUSTOM_PROPERTIES = '
                "{'client_side_timestamps': {'status': 'enabled'}}"
            ),
        },
        "resources": [{"type": "AWS::Cassandra::Table", "ARN": ARN}],
    }


def test_accepted_client_timestamp_enable_matches_catalog_rule(tmp_path: Path):
    (tmp_path / "rule.yml").write_text(
        """title: Synthetic Keyspaces timestamp rule
id: 14700000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: cassandra.amazonaws.com
    event.name: KeyspacesClientSideTimestampsEnabled
    event.outcome: success
    request.keyspaces_client_side_timestamps_enabled: true
  condition: selection
falsepositives: [Approved migration]
level: high
tags: [attack.impact]
x_hacktricks_technique_id: synthetic-keyspaces-timestamps
""", encoding="utf-8")
    hits = detect_aws_events([event()], load_rules(tmp_path, product="aws"))
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert ARN not in str(hits)
    assert "rawquery" not in str(hits).lower()


def test_denial_other_setting_and_foreign_resource_do_not_match():
    accepted = event()
    assert normalize(accepted) is not None
    denied = deepcopy(accepted); denied["errorCode"] = "AccessDeniedException"
    disabled = deepcopy(accepted); disabled["requestParameters"]["rawquery"] = (
        disabled["requestParameters"]["rawquery"].replace("enabled", "disabled")
    )
    unrelated = deepcopy(accepted); unrelated["requestParameters"]["rawquery"] = (
        'ALTER TABLE "synthetic"."records" ADD comment text '
        "/* client_side_timestamps: {'status': 'enabled'} */"
    )
    foreign = deepcopy(accepted); foreign["resources"][0]["ARN"] = ARN.replace(ACCOUNT, "111111111111")
    read_only = deepcopy(accepted); read_only["readOnly"] = True
    assert all(normalize(item) is None for item in (denied, disabled, unrelated, foreign, read_only))
