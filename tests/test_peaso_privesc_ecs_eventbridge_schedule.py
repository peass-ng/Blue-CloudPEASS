"""A scheduled ECS role path needs both the task role and EventBridge invocation role."""

import hashlib
from pathlib import Path

import yaml

from peaso import privesc
from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, reached, role, user


TECHNIQUE = "aws-ecs-eventbridge-scheduled-task-role"
CLUSTER_ARN = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
TASK_ROLE = f"arn:aws:iam::{ACCOUNT}:role/task"
EVENT_ROLE = f"arn:aws:iam::{ACCOUNT}:role/event"
FAMILY = "PeasoPrivesc" + hashlib.sha256((ALICE + TASK_ROLE + REGION).encode()).hexdigest()[:16]
TASK_SCOPE = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{FAMILY}:*"
RULE_ARN = f"arn:aws:events:{REGION}:{ACCOUNT}:rule/{FAMILY}"
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/ecs.yaml"


def _run(*, source_pass_event=True, event_run=True, event_pass_task=True,
         event_trust="events.amazonaws.com", rule_resource=RULE_ARN,
         task_registration=TASK_SCOPE, instance_connected=True, event_inventory="empty",
         event_deny_revision=False, task_trust_source_account=None,
         task_trust_source_arn=None):
    entry = next(row for row in yaml.safe_load(CATALOG.read_text()) if row["id"] == TECHNIQUE)
    grants = [allow("iam:PassRole", resource=TASK_ROLE),
              allow("ecs:RegisterTaskDefinition", resource=task_registration),
              allow("events:PutRule", resource=rule_resource),
              allow("events:PutTargets", resource=rule_resource)]
    if source_pass_event:
        grants.append(allow("iam:PassRole", resource=EVENT_ROLE))
    event_grants = []
    if event_run:
        event_grants.append(allow("ecs:RunTask", resource=TASK_SCOPE))
    if event_pass_task:
        event_grants.append(allow("iam:PassRole", resource=TASK_ROLE))
    if event_deny_revision:
        event_grants.append({"Effect": "Deny", "Action": "ecs:RunTask", "Resource": TASK_SCOPE[:-1] + "2"})
    task_trust = "ecs-tasks.amazonaws.com"
    if task_trust_source_account is not None or task_trust_source_arn is not None:
        conditions = {}
        if task_trust_source_account is not None:
            conditions["StringEquals"] = {"aws:SourceAccount": task_trust_source_account}
        if task_trust_source_arn is not None:
            conditions["ArnLike"] = {"aws:SourceArn": task_trust_source_arn}
        task_trust = [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                       "Action": "sts:AssumeRole",
                       "Condition": conditions}]
    cluster = {"clusterArn": CLUSTER_ARN, "status": "ACTIVE", "registeredContainerInstancesCount": 1}
    instance = {"containerInstanceArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/prod/host",
                "clusterArn": CLUSTER_ARN, "status": "ACTIVE", "agentConnected": instance_connected}
    snap = aws_snap([user("alice", *grants)], roles=[role("task", task_trust),
                    role("event", event_trust, *event_grants)],
                    extra=[col("ecs_cluster", [cluster]), col("ecs_container_instance", [instance]),
                           col("ecs_task_definition", [], status="empty"),
                           col("event_rule", [], status=event_inventory)])
    return privesc.analyze(snap, entries=[entry], include_unknown=True)


def test_new_scheduled_task_reaches_its_task_role():
    assert reached(_run(), ALICE, TECHNIQUE) == {TASK_ROLE: "conditional"}
    recommended = f"arn:aws:ecs:{REGION}:{ACCOUNT}:*"
    assert reached(_run(task_trust_source_account=ACCOUNT, task_trust_source_arn=recommended),
                   ALICE, TECHNIQUE) == {TASK_ROLE: "conditional"}


def test_missing_invocation_role_grant_trust_or_task_scope_does_not_reach():
    assert not reached(_run(source_pass_event=False), ALICE, TECHNIQUE)
    assert not reached(_run(event_run=False), ALICE, TECHNIQUE)
    assert not reached(_run(event_pass_task=False), ALICE, TECHNIQUE)
    assert not reached(_run(event_trust="lambda.amazonaws.com"), ALICE, TECHNIQUE)
    assert not reached(_run(rule_resource=RULE_ARN + "-other"), ALICE, TECHNIQUE)
    assert not reached(_run(task_registration=TASK_SCOPE[:-1] + "1"), ALICE, TECHNIQUE)
    assert not reached(_run(event_deny_revision=True), ALICE, TECHNIQUE)
    assert not reached(_run(task_trust_source_account="222222222222"), ALICE, TECHNIQUE)
    assert not reached(_run(task_trust_source_arn=f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/specific/*"),
                       ALICE, TECHNIQUE)


def test_disconnected_host_and_missing_rule_inventory_are_unresolved():
    assert not reached(_run(instance_connected=False), ALICE, TECHNIQUE)
    result = _run(event_inventory="denied")
    assert not reached(result, ALICE, TECHNIQUE)
    assert result["coverage"] or edges(result, ALICE, TECHNIQUE)
