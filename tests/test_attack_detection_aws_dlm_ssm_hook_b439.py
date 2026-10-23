"""Synthetic derivatives of an owned DLM SSM-script policy lab."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
POLICY = "policy-0123456789abcdef0"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-dlm-role"
DOCUMENT = "synthetic-ssm-document"
RULES = [
    Rule(id="dlm-create", title="DLM SSM hook created", description="synthetic",
         level="medium", product="aws", technique_id="aws-dlm-ssm-hook-policy-created",
         selection={"event.source": "dlm.amazonaws.com", "event.name": "CreateLifecyclePolicy",
                    "event.outcome": "success", "request.dlm_ssm_hook_policy_created": True}),
    Rule(id="dlm-enable", title="DLM SSM hook enabled", description="synthetic",
         level="medium", product="aws", technique_id="aws-dlm-new-ssm-hook-policy-enabled",
         selection={"event.source": "dlm.amazonaws.com", "event.name": "UpdateLifecyclePolicy",
                    "event.outcome": "success", "request.dlm_new_ssm_hook_policy_enabled": True}),
]


def create_event():
    return {
        "eventSource": "dlm.amazonaws.com", "eventName": "CreateLifecyclePolicy",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "eventTime": "2026-10-23T01:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"},
        "requestParameters": {
            "ExecutionRoleArn": ROLE, "State": "DISABLED",
            "PolicyDetails": {"PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
                              "ResourceTypes": ["INSTANCE"],
                              "TargetTags": [{"Key": "SyntheticLab", "Value": "true"}],
                              "Schedules": [{"CreateRule": {"Scripts": [
                                  {"Stages": ["PRE"],
                                   "ExecutionHandlerService": "AWS_SYSTEMS_MANAGER",
                                   "ExecutionHandler": DOCUMENT}]}}]},
        },
        "responseElements": {"PolicyId": POLICY},
    }


def enable_event():
    result = create_event()
    result.update(eventName="UpdateLifecyclePolicy", eventTime="2026-10-23T01:01:00Z",
                  requestParameters={"policyId": POLICY, "State": "ENABLED"},
                  responseElements=None)
    return result


def test_create_then_enable_matches_both_without_raw_role_document_or_policy():
    hits = detect_aws_events([enable_event(), create_event()], RULES)
    assert {hit.technique_id for hit in hits} == {rule.technique_id for rule in RULES}
    assert len(hits) == 2
    assert all(raw not in str(hits) for raw in (ROLE, DOCUMENT, POLICY))


def test_missing_script_denial_and_unrelated_enable_do_not_match():
    create = create_event()
    no_hook = deepcopy(create)
    no_hook["requestParameters"]["PolicyDetails"]["Schedules"][0]["CreateRule"]["Scripts"] = []
    assert detect_aws_events([no_hook, enable_event()], RULES) == []
    denied = deepcopy(create)
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied, enable_event()], RULES) == []
    for change in (
        lambda x: x["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda x: x["requestParameters"].update(policyId="policy-other"),
        lambda x: x.update(eventTime="2026-10-23T03:01:00Z"),
        lambda x: x["requestParameters"].update(State="DISABLED"),
    ):
        other = enable_event()
        change(other)
        hits = detect_aws_events([create, other], RULES)
        assert [hit.technique_id for hit in hits] == [RULES[0].technique_id]
