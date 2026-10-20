"""Synthetic derivatives of an owned CloudWatch dashboard and Insights lab."""

from copy import deepcopy
import json

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-observer/session"
DASHBOARD = "synthetic-dashboard"
RULE = "synthetic-insight-rule"
ARN = f"arn:aws:cloudwatch::{ACCOUNT}:dashboard/{DASHBOARD}"
SECRET = "SYNTHETIC_DASHBOARD_BODY_NEVER_EMIT"
DEFINITION = json.dumps({"Schema": {"Name": "CloudWatchLogRule", "Version": 1},
    "LogGroupNames": ["/peasso/synthetic/insight"], "LogFormat": "JSON",
    "Contribution": {"Keys": ["$.synthetic"], "Filters": []}, "AggregateOn": "Count"})
RULE_IDS = {
    "c69a892f-1660-419e-ad0e-09c851d75c23",
    "2e99fb2c-a911-4e69-8183-6169d59ff5a5",
    "d7314f89-1187-4f0f-8e71-a5c89d3ab4fa",
    "5bd6c23f-8a6b-4241-b9fe-b77a736d718e",
    "c2d7ff2e-2562-4898-9cfc-4d95b721ac0d",
    "8bd0b7fa-6b7d-4788-9680-c55e64156d85",
    "b99f1306-0193-4250-9195-947620ff9ee2",
    "f9cf4a02-cb7f-4f08-8d47-921826275d08",
}


def rules():
    return tuple(x for x in load_rules(product="aws") if x.id in RULE_IDS)


def event(name, request, response=None):
    return {"eventSource": "monitoring.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": name == "GetDashboard",
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": "synthetic-" + name, "eventTime": "2026-10-20T12:00:00Z",
            "userIdentity": {"arn": ACTOR, "accountId": ACCOUNT},
            "requestParameters": request, "responseElements": response}


def events():
    return [
        event("GetDashboard", {"dashboardName": DASHBOARD},
              {"DashboardBody": SECRET}),
        event("PutDashboard", {"dashboardName": DASHBOARD,
              "dashboardBody": "HIDDEN_DUE_TO_SECURITY_REASONS"},
              {"dashboardValidationMessages": []}),
        event("TagResource", {"resourceARN": ARN,
              "tags": [{"key": "synthetic-review", "value": SECRET}]}),
        event("UntagResource", {"resourceARN": ARN,
              "tagKeys": ["synthetic-review"]}),
        event("PutInsightRule", {"ruleName": RULE, "ruleState": "DISABLED",
              "ruleDefinition": DEFINITION}),
        event("EnableInsightRules", {"ruleNames": [RULE]}, {"failures": []}),
        event("DisableInsightRules", {"ruleNames": [RULE]}, {"failures": []}),
        event("DeleteInsightRules", {"ruleNames": [RULE]}, {"failures": []}),
    ]


def test_eight_real_shape_signals_with_no_body_or_tag_value_leak():
    selected = rules()
    hits = detect_aws_events(events(), selected)
    assert len(selected) == len(hits) == len({x.rule_id for x in hits}) == 8
    assert SECRET not in repr(hits)
    assert DEFINITION not in repr(hits)


def test_failed_or_inconsistent_controls_do_not_match():
    selected = rules()
    for original in events():
        failed = deepcopy(original)
        failed["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([failed], selected)
        wrong_read_only = deepcopy(original)
        wrong_read_only["readOnly"] = not original["readOnly"]
        assert not detect_aws_events([wrong_read_only], selected)
    bad_body = deepcopy(events()[1])
    bad_body["requestParameters"]["dashboardBody"] = "not-json-or-redaction"
    assert not detect_aws_events([bad_body], selected)
    failed_batch = deepcopy(events()[5])
    failed_batch["responseElements"]["failures"] = [{"FailureCode": "Forbidden"}]
    assert not detect_aws_events([failed_batch], selected)
    foreign_arn = deepcopy(events()[2])
    foreign_arn["requestParameters"]["resourceARN"] = ARN.replace(ACCOUNT, "111111111111")
    assert not detect_aws_events([foreign_arn], selected)
