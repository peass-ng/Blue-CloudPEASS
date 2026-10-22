"""Exact role and resource joins for selected AWS workload routes."""

from peaso import privesc
from peaso.privesc.schema import load_catalog

from test_peaso_privesc_audit_fixes import reached
from tests.test_peaso_privesc_aws_followups import (
    ALICE, REGION, allow, aws_snap, col, role, role_arn, user,
)
from test_peaso_privesc_batch_existing_definition import QUEUE, ENVIRONMENT
from test_peaso_privesc_apprunner_existing_role import (
    ACCOUNT, OTHER, ROLE, SERVICE, USER, _snapshot as apprunner_snapshot,
)


ENTRIES = {entry["id"]: entry for entry in load_catalog()["entries"]}
CREATE = "aws-apprunner-passrole-createservice"
UPDATE = "aws-apprunner-updateservice-passrole"
BATCH = "aws-batch-registerjobdefinition-passrole-submitjob"
CFN_UPDATE = "aws-cloudformation-updatestack-attached-role"
CFN_CHANGESET = "aws-cloudformation-changeset-attached-role"
STACK = (f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/Existing/"
         "01234567-89ab-4def-8123-456789abcdef")


def _policy(snapshot, actions, resource):
    actor = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": actions, "Resource": resource}]


def _add_policy(snapshot, actions, resource):
    actor = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": actions, "Resource": resource})


def _edges(snapshot, technique):
    result = privesc.analyze(snapshot, entries=[ENTRIES[technique]])
    return reached(result, USER, technique)


def test_apprunner_create_service_needs_passable_role_and_prior_customer():
    snapshot = apprunner_snapshot()
    _policy(snapshot, "apprunner:CreateService", "*")
    _add_policy(snapshot, "iam:PassRole", ROLE)
    assert _edges(snapshot, CREATE) == {ROLE: "conditional"}

    wrong_role = apprunner_snapshot()
    _policy(wrong_role, "apprunner:CreateService", "*")
    _add_policy(wrong_role, "iam:PassRole", "arn:aws:iam::111111111111:role/unrelated")
    assert _edges(wrong_role, CREATE) == {}

    no_prior_service = apprunner_snapshot()
    _policy(no_prior_service, "apprunner:CreateService", "*")
    _add_policy(no_prior_service, "iam:PassRole", ROLE)
    next(c for c in no_prior_service["collections"] if c["type"] == "app_runner_service")["items"] = []
    assert _edges(no_prior_service, CREATE) == {}


def test_apprunner_update_service_needs_exact_service_and_passable_role():
    snapshot = apprunner_snapshot()
    _policy(snapshot, "apprunner:UpdateService", SERVICE)
    _add_policy(snapshot, "iam:PassRole", ROLE)
    assert _edges(snapshot, UPDATE) == {ROLE: "conditional"}

    wrong_service = apprunner_snapshot()
    _policy(wrong_service, "apprunner:UpdateService", SERVICE.replace("/one", "/other"))
    _add_policy(wrong_service, "iam:PassRole", ROLE)
    assert _edges(wrong_service, UPDATE) == {}

    wrong_role = apprunner_snapshot()
    _policy(wrong_role, "apprunner:UpdateService", SERVICE)
    _add_policy(wrong_role, "iam:PassRole", "arn:aws:iam::111111111111:role/unrelated")
    assert _edges(wrong_role, UPDATE) == {}


def _batch_snapshot(*, pass_role=None, queue_state="ENABLED", queue_grant=QUEUE,
                    register=True, submit_definition=True):
    job_role = role_arn("target")
    statements = [allow("iam:PassRole", resource=pass_role or job_role)]
    if register:
        statements.append(allow("batch:RegisterJobDefinition"))
    if submit_definition:
        statements.append(allow("batch:SubmitJob"))
    else:
        statements.append(allow("batch:SubmitJob", resource=queue_grant))
    queue = {"jobQueueArn": QUEUE, "state": queue_state, "status": "VALID",
             "computeEnvironmentOrder": [{"computeEnvironment": ENVIRONMENT, "order": 1}]}
    environment = {"computeEnvironmentArn": ENVIRONMENT, "state": "ENABLED", "status": "VALID",
                   "containerOrchestrationType": "ECS", "computeResources": {"type": "EC2"}}
    return aws_snap([user("alice", *statements)], [role("target", "ecs-tasks.amazonaws.com"),
                    role("other", "ecs-tasks.amazonaws.com")], [col("batch_job_definition", [], "empty"),
                    col("batch_job_queue", [queue]), col("batch_compute_environment", [environment])])


def test_batch_new_job_requires_passrole_and_usable_exact_queue():
    assert reached(privesc.analyze(_batch_snapshot(), entries=[ENTRIES[BATCH]]), ALICE, BATCH) == {
        role_arn("target"): "conditional"}
    for snapshot in (_batch_snapshot(pass_role=role_arn("unrelated")),
                     _batch_snapshot(queue_state="DISABLED"),
                     _batch_snapshot(register=False),
                     _batch_snapshot(submit_definition=False, queue_grant=QUEUE)):
        assert reached(privesc.analyze(snapshot, entries=[ENTRIES[BATCH]]), ALICE, BATCH) == {}


def _cloudformation_snapshot(*, actions, resource=STACK, attached_role=None, status="UPDATE_COMPLETE"):
    target = role("cfn", "cloudformation.amazonaws.com")
    stack = {"StackId": STACK, "StackName": "Existing", "StackStatus": status,
             "RoleARN": attached_role or target["Arn"]}
    return aws_snap([user("alice", allow(*actions, resource=resource))], [target,
                    role("other", "cloudformation.amazonaws.com")],
                    [col("cloudformation_stack", [stack])]), target["Arn"]


def test_cloudformation_attached_role_update_needs_same_stack_and_role():
    snapshot, target = _cloudformation_snapshot(actions=("cloudformation:UpdateStack",))
    assert reached(privesc.analyze(snapshot, entries=[ENTRIES[CFN_UPDATE]]), ALICE, CFN_UPDATE) == {
        target: "conditional"}
    for changes in ({"resource": STACK.replace("/Existing/", "/Different/")},
                    {"attached_role": role_arn("other")}, {"status": "DELETE_COMPLETE"}):
        snapshot, target = _cloudformation_snapshot(actions=("cloudformation:UpdateStack",), **changes)
        assert target not in reached(privesc.analyze(snapshot, entries=[ENTRIES[CFN_UPDATE]]), ALICE, CFN_UPDATE)


def test_cloudformation_attached_role_changeset_needs_both_actions_on_same_stack():
    actions = ("cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet")
    snapshot, target = _cloudformation_snapshot(actions=actions)
    assert reached(privesc.analyze(snapshot, entries=[ENTRIES[CFN_CHANGESET]]), ALICE, CFN_CHANGESET) == {
        target: "conditional"}
    for changes in ({"actions": actions[:1]},
                    {"actions": actions, "resource": STACK.replace("/Existing/", "/Different/")},
                    {"actions": actions, "attached_role": role_arn("other")}):
        snapshot, target = _cloudformation_snapshot(**changes)
        assert target not in reached(privesc.analyze(snapshot, entries=[ENTRIES[CFN_CHANGESET]]), ALICE, CFN_CHANGESET)
