"""An existing Scheduler schedule can write an inline policy only with exact grants."""
from __future__ import annotations

from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, REGION, ALICE, allow, aws_snap, col, role, user,
)


SCHEDULE = f"arn:aws:scheduler:{REGION}:{ACCOUNT}:schedule/team/existing"


def _entry():
    import yaml
    from pathlib import Path
    catalog = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/scheduler.yaml"
    entry = next(row for row in yaml.safe_load(catalog.read_text())
                 if row["id"] == "aws-scheduler-passrole-updateschedule-self-grant")
    assert validate_entry(entry)[0] == []
    return entry


def _schedule(**changes):
    row = {"Arn": SCHEDULE, "Name": "existing", "GroupName": "team", "State": "ENABLED",
           "Target": {}, "_provenance": {"source_operation": "scheduler:GetSchedule",
                                        "kms_key_arn_observed": True}}
    row.update(changes)
    return row


def _reach(*, schedule=None, status="collected", action="scheduler:UpdateSchedule",
           source_grants=(), role_grants=(), trust="scheduler.amazonaws.com"):
    executor = role("scheduled", trust, allow("iam:PutUserPolicy", resource=ALICE), *role_grants)
    caller = user("alice", allow("iam:PassRole", resource=executor["Arn"]),
                  allow(action, resource=SCHEDULE), *source_grants)
    snap = aws_snap([caller], [executor],
                    extra=[col("scheduler_schedule", [_schedule() if schedule is None else schedule], status)])
    return [reach for reach in Evaluator(AwsModel(snap), [_entry()], include_unknown=False).run()
            if reach.source.id == ALICE]


def test_exact_existing_schedule_update_reaches_only_conditional_permission_gain():
    reaches = _reach()
    assert len(reaches) == 1
    assert len(reaches[0].targets) == 1
    assert all(grant.confidence == "conditional" for grant in reaches[0].targets.values())


def test_update_rejects_missing_or_mismatched_schedule_and_extra_key_permissions():
    variants = [
        _schedule(Arn=SCHEDULE.replace(ACCOUNT, "222222222222")),
        _schedule(KmsKeyArn=f"arn:aws:kms:{REGION}:{ACCOUNT}:key/key-id"),
        _schedule(State="DELETED"),
        _schedule(_provenance={"source_operation": "scheduler:GetSchedule"}),
        _schedule(GroupName="other"),
    ]
    for row in variants:
        assert _reach(schedule=row) == [], row
    assert _reach(status="partial") == []
    assert _reach(action="scheduler:CreateSchedule") == []
    assert _reach(trust="lambda.amazonaws.com") == []
    assert _reach(role_grants=[{"Effect": "Deny", "Action": "iam:PutUserPolicy",
                                "Resource": ALICE}]) == []
    assert _reach(source_grants=[allow("iam:CreateUser")]) == []


def test_schedule_collector_preserves_encryption_key_and_read_provenance():
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_ai_recheck_facts_20261020 import schedules

    key = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/key-id"

    class Requests:
        def pages(self, *_args, **_kwargs):
            return ReadResult([{"Name": "existing", "GroupName": "team"}], "collected")

        def detail(self, *_args, **_kwargs):
            return {**_schedule(KmsKeyArn=key), "collection_status": "collected"}

    result = schedules(Requests(), None, REGION, ACCOUNT)
    assert result.status == "collected"
    assert result.items[0]["KmsKeyArn"] == key
    assert result.items[0]["_provenance"]["kms_key_arn_observed"] is True


def test_new_route_keeps_prior_catalog_binding_exact():
    from peaso.privesc.versioned_catalog import (
        BINDING_SCHEMA, SCHEDULER_CREATE_686_PREVIOUS_MANIFEST,
        SCHEDULER_CREATE_686_PREVIOUS_TREE, V4_REVISION,
        current_binding, lookup_entries,
    )

    new = "aws-scheduler-passrole-updateschedule-self-grant"
    old = "aws-scheduler-passrole-createschedule-or-updateschedule"
    current, status = lookup_entries((old, new), current_binding())
    assert status == "exact_strict_privesc" and set(current) == {old, new}
    prior_binding = {"schema": BINDING_SCHEMA,
                     "manifest_sha256": SCHEDULER_CREATE_686_PREVIOUS_MANIFEST,
                     "effective_tree_sha256": SCHEDULER_CREATE_686_PREVIOUS_TREE,
                     "source_revision": V4_REVISION}
    previous, status = lookup_entries((old, new), prior_binding)
    assert status == "exact_previous_current" and set(previous) == {old}
