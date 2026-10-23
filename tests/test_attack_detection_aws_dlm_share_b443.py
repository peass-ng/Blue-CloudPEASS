"""Synthetic derivatives of owned no-target DLM ShareRule labs."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
OTHER = str(int(ACCOUNT) - 1)
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-dlm-role"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"
RULES = [
    Rule(
        id="dlm-share-active", title="Active sharing", level="medium",
        description="synthetic", product="aws",
        technique_id="aws-dlm-active-cross-account-snapshot-share",
        selection={"event.source": "dlm.amazonaws.com", "event.name": "CreateLifecyclePolicy",
                   "event.outcome": "success", "request.dlm_cross_account_share_rule_configured": True,
                   "request.dlm_policy_enabled": True},
    ),
    Rule(
        id="dlm-share-prepared", title="Prepared sharing", level="low",
        description="synthetic", product="aws",
        technique_id="aws-dlm-prepared-cross-account-snapshot-share",
        selection={"event.source": "dlm.amazonaws.com", "event.name": "CreateLifecyclePolicy",
                   "event.outcome": "success", "request.dlm_cross_account_share_rule_configured": True,
                   "request.dlm_policy_enabled": False},
    ),
]


def event(state="ENABLED"):
    return {
        "eventSource": "dlm.amazonaws.com", "eventName": "CreateLifecyclePolicy",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT,
        "eventID": "synthetic-event", "eventTime": "2026-10-23T04:00:00Z",
        "userIdentity": {"arn": ACTOR},
        "requestParameters": {
            "ExecutionRoleArn": ROLE, "State": state,
            "PolicyDetails": {
                "PolicyType": "EBS_SNAPSHOT_MANAGEMENT", "ResourceTypes": ["VOLUME"],
                "TargetTags": [{"Key": "Synthetic", "Value": "unused"}],
                "Schedules": [{"ShareRules": [{"TargetAccounts": [OTHER],
                                               "UnshareInterval": 1, "UnshareIntervalUnit": "DAYS"}]}],
            },
        },
        "responseElements": {"PolicyId": "policy-synthetic"},
    }


def test_enabled_and_prepared_cross_account_share_are_distinct():
    for state, expected in (("ENABLED", RULES[0]), ("DISABLED", RULES[1])):
        hits = detect_aws_events([event(state)], RULES)
        assert len(hits) == 1 and hits[0].technique_id == expected.technique_id
        assert all(value not in str(hits) for value in (ROLE, ACTOR, OTHER))


def test_same_account_missing_share_denied_and_unaccepted_excluded():
    for edit in (
        lambda e: e.update(errorCode="InvalidRequestException"),
        lambda e: e["requestParameters"]["PolicyDetails"]["Schedules"][0].pop("ShareRules"),
        lambda e: e["requestParameters"]["PolicyDetails"]["Schedules"][0]["ShareRules"][0].update(TargetAccounts=[ACCOUNT]),
        lambda e: e["requestParameters"]["PolicyDetails"].update(ResourceTypes=["INSTANCE"]),
        lambda e: e["requestParameters"].pop("ExecutionRoleArn"),
        lambda e: e["responseElements"].pop("PolicyId"),
    ):
        record = deepcopy(event())
        edit(record)
        assert detect_aws_events([record], RULES) == []
