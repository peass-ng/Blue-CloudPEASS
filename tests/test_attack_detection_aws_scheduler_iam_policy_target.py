"""Scheduler IAM policy targets remain visible when CloudTrail omits input."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection.aws_scheduler_iam_policy_target import normalize_aws_scheduler_iam_policy_target
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-2"


def event(*, action="CreateSchedule", kind="Role"):
    name = "synthetic-schedule"
    return {
        "eventSource": "scheduler.amazonaws.com", "eventName": action,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-event", "eventTime": "2026-10-22T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"name": name, "state": "ENABLED",
                              "target": {"arn": f"arn:aws:scheduler:::aws-sdk:iam:put{kind}Policy",
                                         "roleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-executor"}},
        "responseElements": {"scheduleArn": f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/default/{name}"},
    }


def rules(tmp_path):
    for kind, index in (("role", 1), ("user", 2)):
        (tmp_path / f"{kind}.yml").write_text(f"""title: Synthetic Scheduler IAM {kind}
id: b3810000-0000-4000-8000-00000000000{index}
status: experimental
description: Synthetic test rule.
references: [https://example.test/scheduler]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: scheduler.amazonaws.com
    event.outcome: success
    request.scheduler_iam_put_{kind}_policy_target_requested: true
  condition: selection
falsepositives: [Approved schedule]
level: high
x_hacktricks_technique_id: synthetic-scheduler-{kind}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_create_and_update_iam_targets_without_input(tmp_path):
    events = [event(action=action, kind=kind)
              for action in ("CreateSchedule", "UpdateSchedule") for kind in ("Role", "User")]
    hits = detect_aws_events(events, rules(tmp_path))
    assert len(hits) == 4
    assert {hit.technique_id for hit in hits} == {"synthetic-scheduler-role", "synthetic-scheduler-user"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)


def test_wrong_target_denial_or_foreign_role_excluded(tmp_path):
    base = event()
    variants = []
    changes = (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x.update(eventSource="other.amazonaws.com"),
        lambda x: x["requestParameters"]["target"].update(arn="arn:aws:scheduler:::aws-sdk:s3:putObject"),
        lambda x: x["requestParameters"]["target"].update(roleArn=f"arn:aws:iam::111111111111:role/foreign"),
        lambda x: x["responseElements"].update(scheduleArn="other"),
        lambda x: x["requestParameters"].update(name="wrong/name"),
    )
    for change in changes:
        variant = deepcopy(base)
        change(variant)
        variants.append(variant)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_non_iam_policy_target_is_not_recognized():
    value = event()
    value["requestParameters"]["target"]["arn"] = "arn:aws:scheduler:::aws-sdk:iam:deleteRolePolicy"
    assert normalize_aws_scheduler_iam_policy_target(value) is None
