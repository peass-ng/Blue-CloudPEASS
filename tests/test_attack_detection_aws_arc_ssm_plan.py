"""ARC SSM plan signals require accepted, response-confirmed workflows."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.aws_arc_ssm_plan import normalize_aws_arc_ssm_plan
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
PLAN = f"arn:aws:arc-region-switch::{ACCOUNT}:plan/synthetic:abcdef"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-arc"
SENTINEL = "private-command-and-target"


def event(name: str = "CreatePlan") -> dict:
    workflows = [{
        "workflowTargetAction": "activate", "workflowTargetRegion": "us-east-2",
        "steps": [{"name": "synthetic-command", "executionBlockType": "SSMSendCommand",
                   "executionBlockConfiguration": {"ssmSendCommandConfig": {
                       "regionDocuments": {"us-east-2": {
                           "documentArn": "arn:aws:ssm:us-east-2::document/AWS-RunShellScript",
                           "targets": [{"key": "tag:synthetic", "values": [SENTINEL]}],
                           "parameters": {"commands": [SENTINEL]},
                       }}
                   }}}]}]
    request = {"executionRole": ROLE, "workflows": workflows,
               "name": "synthetic"} if name == "CreatePlan" else {
                   "executionRole": ROLE, "workflows": workflows, "arn": PLAN}
    return {
        "eventSource": "arc-region-switch.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": f"synthetic-{name}", "eventTime": "2026-10-22T12:00:00Z",
        "userIdentity": {"accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": request,
        "responseElements": {"plan": {"arn": PLAN, "owner": ACCOUNT,
                                      "executionRole": ROLE, "name": "synthetic",
                                      "workflows": workflows}},
    }


def rules(tmp_path: Path):
    for name, flag in (("CreatePlan", "created"), ("UpdatePlan", "updated")):
        (tmp_path / f"{name}.yml").write_text(f"""title: Synthetic ARC {name}
id: b3710000-0000-4000-8000-00000000000{1 if name == 'CreatePlan' else 2}
status: experimental
description: Synthetic test rule.
references: [https://example.test/arc]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: arc-region-switch.amazonaws.com
    event.name: {name}
    event.outcome: success
    request.arc_ssm_command_plan_{flag}: true
  condition: selection
falsepositives: [Approved recovery]
level: high
x_hacktricks_technique_id: synthetic-arc-{flag}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_create_and_update_plan_match_without_commands_or_arns(tmp_path):
    selected = rules(tmp_path)
    hits = detect_aws_events([event("CreatePlan"), event("UpdatePlan")], selected)
    assert len(hits) == 2
    assert {hit.technique_id for hit in hits} == {"synthetic-arc-created", "synthetic-arc-updated"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert SENTINEL not in str(hits)
    assert ROLE not in str(hits)
    assert PLAN not in str(hits)


def test_denials_foreign_roles_and_unconfirmed_workflows_are_excluded(tmp_path):
    selected = rules(tmp_path)
    base = event()
    variants = []
    for change in (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x["userIdentity"].update(accountId="111111111111"),
        lambda x: x["requestParameters"].update(executionRole=ROLE.replace(ACCOUNT, "111111111111")),
        lambda x: x["responseElements"]["plan"].update(executionRole="other"),
        lambda x: x["responseElements"]["plan"].update(workflows=[]),
        lambda x: x["responseElements"]["plan"].update(owner="111111111111"),
        lambda x: x["responseElements"]["plan"].update(arn=PLAN.replace(ACCOUNT, "111111111111")),
        lambda x: x["requestParameters"]["workflows"][0]["steps"][0].update(
            executionBlockType="ExecutionApproval"),
        lambda x: x["requestParameters"].update(name="different"),
    ):
        item = deepcopy(base)
        change(item)
        variants.append(item)
    assert detect_aws_events(variants, selected) == []


def test_nested_parallel_ssm_step_is_detected(tmp_path):
    item = event()
    step = item["requestParameters"]["workflows"][0]["steps"][0]
    item["requestParameters"]["workflows"][0]["steps"] = [{
        "executionBlockType": "Parallel",
        "executionBlockConfiguration": {"parallelConfig": {"steps": [step]}},
    }]
    assert normalize_aws_arc_ssm_plan(item) is not None
    assert len(detect_aws_events([item], rules(tmp_path))) == 1


def test_update_must_reference_confirmed_plan(tmp_path):
    item = event("UpdatePlan")
    item["requestParameters"]["arn"] = PLAN.replace("synthetic", "other")
    assert detect_aws_events([item], rules(tmp_path)) == []
