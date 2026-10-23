"""Synthetic derivatives of observed Migration Hub Strategy management events."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection.aws_migration_strategy_inventory import (
    correlate_aws_migration_strategy_inventory,
)
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
ACTIONS = (
    "ListCollectors", "ListServers", "ListApplicationComponents",
    "ListImportFileTask", "GetPortfolioPreferences",
)
READ_ONLY = {"ListCollectors": True, "ListServers": False,
             "ListApplicationComponents": False, "ListImportFileTask": True,
             "GetPortfolioPreferences": True}


def event(action: str, minute: int) -> dict:
    stamp = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return {
        "eventSource": "migrationhub-strategy.amazonaws.com",
        "eventName": action, "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": READ_ONLY[action], "recipientAccountId": ACCOUNT,
        "awsRegion": REGION, "eventID": f"synthetic-{minute}-{action}",
        "eventTime": stamp.isoformat().replace("+00:00", "Z"),
        "userIdentity": {"accountId": ACCOUNT, "arn": ACTOR},
        "responseElements": {"syntheticSensitiveMarker": "never-in-finding"},
    }


def sweep() -> list[dict]:
    return [event(action, minute) for minute, action in enumerate(ACTIONS)]


def rules(tmp_path):
    (tmp_path / "migration.yml").write_text("""title: Synthetic migration sweep
id: b3850000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/migration]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: migrationhub-strategy.amazonaws.com
    event.name: MigrationStrategyInventorySweep
    event.outcome: success
    request.migration_strategy_inventory_sweep: true
  condition: selection
falsepositives: [Approved inventory sweep]
level: medium
x_hacktricks_technique_id: synthetic-migration-inventory-sweep
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_realistic_sweep_correlates_order_independently_and_redacts_response(tmp_path):
    events = sweep()
    assert len(correlate_aws_migration_strategy_inventory(list(reversed(events)))) == 1
    hits = detect_aws_events(list(reversed(events)), rules(tmp_path))
    assert [hit.technique_id for hit in hits] == ["synthetic-migration-inventory-sweep"]
    assert hits[0].target_id.startswith("sha256:")
    assert "never-in-finding" not in str(hits)


def test_requires_five_distinct_actions_same_actor_account_region_and_window():
    base = sweep()
    for index in range(5):
        assert not correlate_aws_migration_strategy_inventory(base[:index] + base[index + 1:])
    for change in (
        lambda e: e["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda e: e.update(recipientAccountId="111111111111"),
        lambda e: e.update(awsRegion="us-west-2"),
        lambda e: e.update(eventTime="2026-10-23T12:30:00Z"),
    ):
        variant = deepcopy(base)
        change(variant[-1])
        assert not correlate_aws_migration_strategy_inventory(variant)


def test_failed_or_malformed_management_events_do_not_correlate():
    base = sweep()
    for change in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=not READ_ONLY[e["eventName"]]),
        lambda e: e.update(managementEvent=False),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e.update(eventType="AwsServiceEvent"),
        lambda e: e.update(eventID=""),
        lambda e: e["userIdentity"].update(accountId="111111111111"),
    ):
        variant = deepcopy(base)
        change(variant[-1])
        assert not correlate_aws_migration_strategy_inventory(variant)


def test_duplicate_api_does_not_replace_missing_action():
    base = sweep()
    base[-1] = event("ListCollectors", 4)
    assert not correlate_aws_migration_strategy_inventory(base)
