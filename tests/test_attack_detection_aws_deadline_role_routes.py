"""Deadline Cloud role-change signals use only accepted and correlated events."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
OTHER = "111111111111"
FARM = "farm-synthetic"
FLEET = "fleet-synthetic"
QUEUE = "queue-synthetic"
WORKER = "worker-synthetic"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-deadline-role"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
SIGNALS = (
    ("CreateFleet", "deadline_customer_managed_fleet_role_created", "aws-deadline-customer-managed-fleet-role-created"),
    ("CreateQueue", "deadline_queue_role_created", "aws-deadline-queue-role-created"),
    ("UpdateQueue", "deadline_queue_role_update_requested", "aws-deadline-queue-role-update-requested"),
    ("AssumeFleetRoleForWorker", "deadline_worker_role_vended_after_registration", "aws-deadline-worker-role-vended-after-registration"),
    ("AssumeQueueRoleForUser", "deadline_queue_role_vended_after_update", "aws-deadline-queue-role-vended-after-update"),
)


def event(name: str, *, minute: int = 0, event_id: str | None = None) -> dict:
    request = {"farmId": FARM}
    response = {}
    if name in {"CreateQueue", "UpdateQueue", "AssumeQueueRoleForUser"}:
        if name != "CreateQueue":
            request["queueId"] = QUEUE
        if name in {"CreateQueue", "UpdateQueue"}:
            request["roleArn"] = ROLE
        if name == "CreateQueue":
            response["queueId"] = QUEUE
    if name in {"CreateFleet", "UpdateFleet", "CreateWorker", "AssumeFleetRoleForWorker"}:
        if name != "CreateFleet":
            request["fleetId"] = FLEET
        if name in {"CreateFleet", "UpdateFleet"}:
            request["roleArn"] = ROLE
        if name == "CreateFleet":
            request["configuration"] = {"customerManaged": {"mode": "NO_SCALING"}}
            response["fleetId"] = FLEET
        if name == "CreateWorker":
            response["workerId"] = WORKER
        if name == "AssumeFleetRoleForWorker":
            request["workerId"] = WORKER
    return {
        "eventSource": "deadline.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": name.startswith("Assume"),
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
        "eventTime": f"2026-10-22T12:{minute:02d}:00Z",
        "eventID": event_id or f"synthetic-{name}-{minute}",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
        "requestParameters": request, "responseElements": response,
        "resources": [],
    }


def rules(tmp_path: Path):
    for i, (name, flag, technique) in enumerate(SIGNALS, 1):
        (tmp_path / f"deadline-{i}.yml").write_text(f"""title: Synthetic Deadline signal {i}
id: b3680000-0000-4000-8000-{i:012d}
status: experimental
description: Synthetic test rule.
references: [https://example.test/deadline]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: deadline.amazonaws.com
    event.name: {name}
    event.outcome: success
    request.{flag}: true
  condition: selection
falsepositives: [Authorized operation]
level: medium
x_hacktricks_technique_id: {technique}
""")
    return load_rules(tmp_path, product="aws")


def test_role_assignments_and_both_vending_sequences(tmp_path):
    selected = rules(tmp_path)
    records = [event("CreateFleet"), event("CreateQueue"),
               event("CreateWorker", minute=1), event("UpdateQueue", minute=2),
               event("AssumeFleetRoleForWorker", minute=3),
               event("AssumeQueueRoleForUser", minute=4)]
    hits = detect_aws_events(list(reversed(records)), selected)
    ids = {hit.technique_id for hit in hits}
    assert len(hits) == 5
    assert {"aws-deadline-customer-managed-fleet-role-created",
            "aws-deadline-queue-role-created",
            "aws-deadline-queue-role-update-requested",
            "aws-deadline-worker-role-vended-after-registration",
            "aws-deadline-queue-role-vended-after-update"} <= ids
    assert ROLE not in str(hits)
    assert FARM not in str(hits)


def test_role_assignment_rejects_denial_foreign_role_and_unrelated_update(tmp_path):
    selected = rules(tmp_path)
    variants = []
    for name in ("CreateFleet", "CreateQueue", "UpdateQueue"):
        base = event(name)
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data", "managementEvent": False},
                       {"readOnly": True}):
            variant = deepcopy(base); variant.update(change); variants.append(variant)
        foreign = deepcopy(base); foreign["requestParameters"]["roleArn"] = ROLE.replace(ACCOUNT, OTHER)
        variants.append(foreign)
        unrelated = deepcopy(base); unrelated["requestParameters"].pop("roleArn")
        variants.append(unrelated)
    wrong_fleet = event("CreateFleet");wrong_fleet["requestParameters"]["configuration"] = {"serviceManagedEc2": {}}
    variants.append(wrong_fleet)
    assert detect_aws_events(variants, selected) == []


def test_correlations_require_same_actor_resource_account_and_window(tmp_path):
    selected = rules(tmp_path)
    sequences = (("CreateWorker", "AssumeFleetRoleForWorker"),
                 ("UpdateQueue", "AssumeQueueRoleForUser"))
    for first, second in sequences:
        start, vend = event(first), event(second, minute=2)
        valid = detect_aws_events([start, vend], selected)
        assert any(x.technique_id.endswith("after-registration") or
                   x.technique_id.endswith("after-update") for x in valid)
        for changed in (
            lambda x: x["userIdentity"].update({"arn": f"arn:aws:iam::{ACCOUNT}:user/other"}),
            lambda x: x["requestParameters"].update({"farmId": "farm-other"}),
            lambda x: x["requestParameters"].update({"workerId": "worker-other"} if second == "AssumeFleetRoleForWorker" else {"queueId": "queue-other"}),
            lambda x: x.update({"recipientAccountId": OTHER}),
            lambda x: x.update({"eventTime": "2026-10-22T12:31:00Z"}),
            lambda x: x.update({"errorCode": "AccessDeniedException"}),
        ):
            altered = deepcopy(vend);changed(altered)
            hits = detect_aws_events([start, altered], selected)
            assert not any(x.technique_id.endswith("after-registration") or
                           x.technique_id.endswith("after-update") for x in hits)


def test_duplicate_vending_event_does_not_duplicate_correlation(tmp_path):
    selected = rules(tmp_path)
    start, vend = event("CreateWorker"), event("AssumeFleetRoleForWorker", minute=1)
    hits = detect_aws_events([vend, start, deepcopy(vend)], selected)
    assert sum(x.technique_id == "aws-deadline-worker-role-vended-after-registration" for x in hits) == 1
