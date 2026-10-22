"""Exact graph cases for SSM association, Automation, and maintenance routes."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached,
    role, role_arn, user,
)


NODE_ROLE = role_arn("node")
AUTOMATION_ROLE = role_arn("automation")
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/node"
WINDOW = f"arn:aws:ssm:{REGION}:{ACCOUNT}:maintenancewindow/mw-123"


def _managed_instance(*, state="running", ping="Online"):
    node = role("node", "ec2.amazonaws.com", profiles=[PROFILE])
    instance = {"InstanceId": "i-123", "State": {"Name": state},
                "IamInstanceProfile": {"Arn": PROFILE}}
    managed = {"InstanceId": "i-123", "PingStatus": ping}
    return node, [col("instance", [instance]), col("ssm_managed_instance", [managed])]


def test_create_association_requires_online_instance_and_shell_document_scope():
    tid = "aws-ssm-createassociation"
    def run(*, action="*", state="running", ping="Online"):
        node, inventory = _managed_instance(state=state, ping=ping)
        return reached(real(aws_snap([user("alice", allow("ssm:CreateAssociation", resource=action))],
                                     [node], inventory), tid), ALICE, tid)
    assert NODE_ROLE in run()
    assert NODE_ROLE not in run(action=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-123")
    assert NODE_ROLE not in run(state="stopped")
    assert NODE_ROLE not in run(ping="ConnectionLost")


def _window_inventory(*, enabled=True):
    window = {"WindowId": "mw-123", "Enabled": enabled, "NextExecutionTime": "2026-10-24T00:00:00Z",
              "Tasks": {"collection_status": "empty", "items": []}}
    return col("ssm_maintenance_window", [window])


def test_maintenance_window_run_command_requires_enabled_window_and_exact_task_grant():
    tid = "aws-ssm-maintenancewindow-register-task-target"
    def run(*, writer=WINDOW, enabled=True):
        node, inventory = _managed_instance()
        actor = user("alice", allow("ssm:RegisterTaskWithMaintenanceWindow", resource=writer))
        return reached(real(aws_snap([actor], [node], [*inventory, _window_inventory(enabled=enabled)]), tid), ALICE, tid)
    assert NODE_ROLE in run()
    assert NODE_ROLE not in run(writer=WINDOW.replace("mw-123", "mw-other"))
    assert NODE_ROLE not in run(enabled=False)


def _automation_snapshot(*, pass_arn=AUTOMATION_ROLE, create_doc=True, start=True,
                         window=False, window_enabled=True, incident=False, active=True):
    grants = [allow("iam:PassRole", resource=pass_arn)]
    if create_doc:
        grants.append(allow("ssm:CreateDocument"))
    if start:
        grants.append(allow("ssm:StartAutomationExecution"))
    extra = [col("ssm_document_metadata", [], status="empty")]
    if window:
        grants.append(allow("ssm:RegisterTaskWithMaintenanceWindow", resource=WINDOW))
        extra.append(_window_inventory(enabled=window_enabled))
    if incident:
        grants.extend([allow("ssm-incidents:CreateResponsePlan"), allow("ssm-incidents:StartIncident")])
        replication = {"status": "ACTIVE" if active else "INACTIVE",
                       "regionMap": {REGION: {"status": "ACTIVE" if active else "INACTIVE"}}}
        account = {"ReplicationSets": {"collection_status": "collected", "items": [replication]},
                   "ResponsePlans": {"collection_status": "empty", "items": []}}
        extra.append(col("ssmincidents_account", [account]))
    target_grants = [allow("ssm:StartAutomationExecution")] if incident else []
    trust = "ssm-incidents.amazonaws.com" if incident else "ssm.amazonaws.com"
    target = role("automation", trust, *target_grants)
    return aws_snap([user("alice", *grants)], [target], extra)


def test_new_automation_document_requires_passable_ssm_role_and_start_permission():
    tid = "aws-ssm-createdocument-startautomationexecution-passrole"
    assert AUTOMATION_ROLE in reached(real(_automation_snapshot(), tid), ALICE, tid)
    assert AUTOMATION_ROLE not in reached(real(_automation_snapshot(pass_arn=NODE_ROLE), tid), ALICE, tid)
    assert AUTOMATION_ROLE not in reached(real(_automation_snapshot(start=False), tid), ALICE, tid)
    assert AUTOMATION_ROLE not in reached(real(_automation_snapshot(create_doc=False), tid), ALICE, tid)


def test_maintenance_window_automation_requires_schedule_document_and_passable_role():
    tid = "aws-ssm-maintenancewindow-automation-task-passrole"
    def run(**kwargs):
        return reached(real(_automation_snapshot(window=True, start=False, **kwargs), tid), ALICE, tid)
    assert AUTOMATION_ROLE in run()
    assert AUTOMATION_ROLE not in run(pass_arn=NODE_ROLE)
    assert AUTOMATION_ROLE not in run(window_enabled=False)
    assert AUTOMATION_ROLE not in run(create_doc=False)


def test_incident_response_plan_requires_active_replication_and_executable_runbook():
    tid = "aws-ssm-incidents-response-plan-automation-passrole"
    def run(**kwargs):
        return reached(real(_automation_snapshot(incident=True, **kwargs), tid), ALICE, tid)
    assert AUTOMATION_ROLE in run()
    assert AUTOMATION_ROLE not in run(pass_arn=NODE_ROLE)
    assert AUTOMATION_ROLE not in run(active=False)
    assert AUTOMATION_ROLE not in run(create_doc=False)
