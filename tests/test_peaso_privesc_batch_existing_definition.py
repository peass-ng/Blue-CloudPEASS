"""SubmitJob uses the exact job role from an active, runnable definition."""

import pytest

from peaso.collectors import aws_facts_swc as facts
from peaso.privesc import versioned_catalog
from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, role_arn, user,
)


TECHNIQUE = "aws-batch-submitjob-existing-definition"
DEFINITION = f"arn:aws:batch:{REGION}:{ACCOUNT}:job-definition/etl:4"
QUEUE = f"arn:aws:batch:{REGION}:{ACCOUNT}:job-queue/compute"
ENVIRONMENT = f"arn:aws:batch:{REGION}:{ACCOUNT}:compute-environment/ec2"


def test_job_definition_projection_retains_role_and_drops_environment_values():
    raw = {"jobDefinitionArn": DEFINITION, "jobDefinitionName": "etl", "revision": 4,
           "status": "ACTIVE", "type": "container", "platformCapabilities": ["EC2"],
           "containerProperties": {"jobRoleArn": role_arn("target"), "image": "example/image:tag",
                                   "environment": [{"name": "SECRET", "value": "do-not-store"}]}}
    [item] = facts.ENRICHERS["batch_job_definition"](None, None, REGION, [raw])
    assert item["containerProperties"] == {"jobRoleArn": role_arn("target"), "image": "example/image:tag"}
    assert item["jobDefinitionArn"] == DEFINITION and item["revision"] == 4
    assert "do-not-store" not in str(item)


def scenario(*, role_name="target", definition_arn=DEFINITION, revision=4, status="ACTIVE",
             platform=None, queue_arn=QUEUE, queue_state="ENABLED", environment_type="EC2",
             definition_grant=True, queue_grant=True, inventory_status="collected"):
    statements = []
    if definition_grant:
        statements.append(allow("batch:SubmitJob", resource=DEFINITION))
    if queue_grant:
        statements.append(allow("batch:SubmitJob", resource=QUEUE))
    caller = user("alice", *statements)
    definition = {"jobDefinitionArn": definition_arn, "jobDefinitionName": "etl", "revision": revision,
                  "status": status, "type": "container", "platformCapabilities": platform,
                  "containerProperties": {"jobRoleArn": role_arn(role_name), "image": "example/image:tag"}}
    queue = {"jobQueueArn": queue_arn, "state": queue_state, "status": "VALID",
             "computeEnvironmentOrder": [{"computeEnvironment": ENVIRONMENT, "order": 1}]}
    environment = {"computeEnvironmentArn": ENVIRONMENT, "state": "ENABLED", "status": "VALID",
                   "containerOrchestrationType": "ECS", "computeResources": {"type": environment_type}}
    extra = [col("batch_job_definition", [definition], inventory_status),
             col("batch_job_queue", [queue]), col("batch_compute_environment", [environment])]
    snap = aws_snap([caller], [role("target", "ecs-tasks.amazonaws.com"),
                               role("other", "ecs-tasks.amazonaws.com")], extra)
    return reached(real(snap, TECHNIQUE, include_unknown=True), ALICE, TECHNIQUE)


def test_submit_job_only_reaches_recorded_role_without_passrole():
    assert scenario() == {role_arn("target"): "conditional"}
    assert scenario(role_name="other") == {role_arn("other"): "conditional"}


@pytest.mark.parametrize("change", (
    {"definition_arn": DEFINITION.replace(":4", ":5")},
    {"status": "INACTIVE"}, {"platform": ["FARGATE"]},
    {"queue_arn": QUEUE.replace("compute", "wrong")}, {"queue_state": "DISABLED"},
    {"environment_type": "FARGATE"}, {"definition_grant": False}, {"queue_grant": False},
))
def test_wrong_revision_queue_state_platform_or_grant_cannot_reach_role(change):
    assert scenario(**change) == {}


def test_missing_definition_inventory_cannot_make_a_role_edge():
    assert scenario(inventory_status="access_denied") == {}


def test_previous_catalog_keeps_athena_paths_without_new_batch_path():
    old = {"schema": versioned_catalog.BINDING_SCHEMA,
           "manifest_sha256": versioned_catalog.ATHENA_CURRENT_MANIFEST,
           "effective_tree_sha256": versioned_catalog.ATHENA_CURRENT_TREE,
           "source_revision": versioned_catalog.V4_REVISION}
    entries, status = versioned_catalog.lookup_entries(
        [TECHNIQUE, "aws-athena-startcalculationexecution-existing-session"], old)
    assert status == "exact_previous_current"
    assert set(entries) == {"aws-athena-startcalculationexecution-existing-session"}
