"""Synthetic derivatives of the owned AMP workspace management lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
WORKSPACE = "ws-synthetic"
IDS = {"aws-amp-" + name for name in (
    "rule-file-read", "rule-file-replaced", "alertmanager-read",
    "alertmanager-replaced", "retention-one-day", "query-logging-deleted")}


def event(name, request, response, index, read=False):
    return {"eventSource": "aps.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": read,
            "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
            "eventID": f"33333333-3333-4333-8333-{index:012d}",
            "eventTime": "2026-10-21T00:00:00Z",
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": {"workspaceId": WORKSPACE, **request},
            "responseElements": response}


def fixtures():
    return [
        event("DescribeRuleGroupsNamespace", {"name": "synthetic"}, None, 1, read=True),
        event("PutRuleGroupsNamespace", {"name": "synthetic", "data": "Z3JvdXBzOiBbXQ=="},
              {"name": "synthetic", "status": {"statusCode": "UPDATING"}}, 2),
        event("DescribeAlertManagerDefinition", {}, None, 3, read=True),
        event("PutAlertManagerDefinition", {"data": "YWxlcnRtYW5hZ2VyX2NvbmZpZzoge30="},
              {"status": {"statusCode": "UPDATING"}}, 4),
        event("UpdateWorkspaceConfiguration", {"retentionPeriodInDays": 1},
              {"status": {"statusCode": "UPDATING"}}, 5),
        event("DeleteQueryLoggingConfiguration", {},
              {"Access-Control-Expose-Headers": "x-amzn-RequestId"}, 6),
    ]


def rules():
    return [r for r in load_rules(product="aws") if r.technique_id in IDS]


def test_six_management_routes_match_without_definition_body():
    selected = rules()
    assert len(selected) == 6
    hits = detect_aws_events(fixtures(), selected)
    assert len(hits) == 6
    assert {hit.technique_id for hit in hits} == IDS
    assert "Z3JvdXBzOiBbXQ==" not in str(hits)
    assert "YWxlcnRtYW5hZ2VyX2NvbmZpZzoge30=" not in str(hits)


def test_errors_and_unconfirmed_updates_do_not_match():
    selected = rules()
    for source in fixtures():
        denied = deepcopy(source)
        denied["errorCode"] = "AccessDeniedException"
        assert detect_aws_events([denied], selected) == []
    records = deepcopy(fixtures())
    records[1]["responseElements"]["status"]["statusCode"] = "UPDATE_FAILED"
    records[3]["responseElements"]["status"]["statusCode"] = "UPDATE_FAILED"
    records[4]["requestParameters"]["retentionPeriodInDays"] = 150
    assert {h.technique_id for h in detect_aws_events(records, selected)} == {
        "aws-amp-rule-file-read", "aws-amp-alertmanager-read", "aws-amp-query-logging-deleted"}


def test_inconsistent_namespace_and_failed_delete_are_excluded():
    selected = rules()
    records = deepcopy(fixtures())
    records[1]["responseElements"]["name"] = "other"
    records[5]["responseElements"]["message"] = "ResourceNotFoundException"
    assert {h.technique_id for h in detect_aws_events(records, selected)} == IDS - {
        "aws-amp-rule-file-replaced", "aws-amp-query-logging-deleted"}
