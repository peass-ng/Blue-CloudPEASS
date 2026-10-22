"""ARC Lambda plan writes expose only confirmed configuration flags."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection.aws_arc_lambda_plan import normalize_aws_arc_lambda_plan
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
PLAN = f"arn:aws:arc-region-switch::{ACCOUNT}:plan/synthetic:abcdef"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-arc"
PAYLOAD = "private-lambda-payload"


def event(name="CreatePlan"):
    functions = [{"arn": f"arn:aws:lambda:{region}:{ACCOUNT}:function:synthetic",
                  "payload": PAYLOAD} for region in ("us-east-1", "us-east-2")]
    workflows = [{"workflowTargetAction": "activate", "workflowTargetRegion": "us-east-2",
                  "steps": [{"name": "synthetic", "executionBlockType": "CustomActionLambda",
                             "executionBlockConfiguration": {"customActionLambdaConfig": {
                                 "lambdas": functions, "regionToRun": "activatingRegion",
                                 "timeoutMinutes": 5, "retryIntervalMinutes": 1}}}]}]
    request = {"executionRole": ROLE, "workflows": workflows,
               "name": "synthetic"} if name == "CreatePlan" else {
                   "executionRole": ROLE, "workflows": workflows, "arn": PLAN}
    return {"eventSource": "arc-region-switch.amazonaws.com", "eventName": name,
            "eventType": "AwsApiCall", "eventCategory": "Management",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": "synthetic-" + name, "eventTime": "2026-10-22T12:00:00Z",
            "userIdentity": {"accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
            "requestParameters": request,
            "responseElements": {"plan": {"arn": PLAN, "owner": ACCOUNT,
                                          "executionRole": ROLE, "name": "synthetic",
                                          "workflows": deepcopy(workflows)}}}


def rules(tmp_path):
    for name, suffix in (("CreatePlan", "created"), ("UpdatePlan", "updated")):
        (tmp_path / (name + ".yml")).write_text(f"""title: Synthetic ARC Lambda {name}
id: b3730000-0000-4000-8000-00000000000{1 if name == 'CreatePlan' else 2}
status: experimental
description: Synthetic test rule.
references: [https://example.test/arc-lambda]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: arc-region-switch.amazonaws.com
    event.name: {name}
    event.outcome: success
    request.arc_lambda_action_plan_{suffix}: true
  condition: selection
falsepositives: [Approved recovery]
level: high
x_hacktricks_technique_id: synthetic-arc-lambda-{suffix}
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def test_create_and_update_accepted_lambda_plans_match_without_private_values(tmp_path):
    hits = detect_aws_events([event(), event("UpdatePlan")], rules(tmp_path))
    assert len(hits) == 2
    assert {h.technique_id for h in hits} == {"synthetic-arc-lambda-created",
                                                 "synthetic-arc-lambda-updated"}
    assert all(h.target_id.startswith("sha256:") for h in hits)
    assert PAYLOAD not in str(hits)
    assert PLAN not in str(hits)
    assert ROLE not in str(hits)


def test_denied_unconfirmed_and_malformed_lambda_plans_do_not_match(tmp_path):
    base = event()
    variants = []
    for change in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=True),
        lambda e: e["userIdentity"].update(accountId="111111111111"),
        lambda e: e["requestParameters"].update(executionRole=ROLE.replace(ACCOUNT, "111111111111")),
        lambda e: e["responseElements"]["plan"].update(workflows=[]),
        lambda e: e["responseElements"]["plan"].update(owner="111111111111"),
        lambda e: e["requestParameters"].update(name="other"),
        lambda e: e["requestParameters"]["workflows"][0]["steps"][0]["executionBlockConfiguration"]["customActionLambdaConfig"].update(regionToRun="unknown"),
        lambda e: e["requestParameters"]["workflows"][0]["steps"][0]["executionBlockConfiguration"]["customActionLambdaConfig"].update(lambdas=[]),
        lambda e: e["requestParameters"]["workflows"][0]["steps"][0].update(executionBlockType="ExecutionApproval"),
    ):
        item = deepcopy(base)
        change(item)
        variants.append(item)
    same_region = deepcopy(base)
    same_region["requestParameters"]["workflows"][0]["steps"][0]["executionBlockConfiguration"]["customActionLambdaConfig"]["lambdas"][1]["arn"] = (
        f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:synthetic")
    variants.append(same_region)
    assert detect_aws_events(variants, rules(tmp_path)) == []


def test_parallel_lambda_step_is_detected_and_update_arn_must_match(tmp_path):
    nested = event()
    steps = nested["requestParameters"]["workflows"][0]["steps"]
    nested["requestParameters"]["workflows"][0]["steps"] = [{
        "executionBlockType": "Parallel",
        "executionBlockConfiguration": {"parallelConfig": {"steps": steps}},
    }]
    nested["responseElements"]["plan"]["workflows"] = deepcopy(nested["requestParameters"]["workflows"])
    assert normalize_aws_arc_lambda_plan(nested) is not None
    assert len(detect_aws_events([nested], rules(tmp_path))) == 1
    wrong = event("UpdatePlan")
    wrong["requestParameters"]["arn"] = PLAN.replace("synthetic", "other")
    assert detect_aws_events([wrong], rules(tmp_path)) == []
