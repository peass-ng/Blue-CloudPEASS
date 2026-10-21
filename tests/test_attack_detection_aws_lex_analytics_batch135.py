"""Synthetic derivatives of isolated Lex V2 analytics and export labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
BOT = "SYNTHBOT01"
EXPORT = "SYNTHEXP01"
IDS = {
    "aws-lex-v2-aggregated-utterances-listed",
    "aws-lex-v2-utterance-analytics-listed",
    "aws-lex-v2-session-analytics-listed",
    "aws-lex-v2-bot-model-export-created",
    "aws-lex-v2-bot-model-export-described",
    "aws-lex-v2-bot-model-export-deleted",
    "aws-lex-v2-utterances-deleted",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 7
    return selected


def event(name, index, request, response=None, *, read=False):
    return {
        "eventSource": "lex.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T11:40:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    dates = {"botId": BOT, "startDateTime": 1792560000, "endDateTime": 1792563600}
    return [
        event("ListAggregatedUtterances", 1, {"botId": BOT, "botAliasId": "TSTALIASID",
                                                "localeId": "en_US", "aggregationDuration": {
                                                    "relativeAggregationDuration": {"timeDimension": "Hours", "timeValue": 24}}}, read=True),
        event("ListUtteranceAnalyticsData", 2, dates, read=True),
        event("ListSessionAnalyticsData", 3, dates, read=True),
        event("CreateExport", 4, {"resourceSpecification": {"botExportSpecification": {
            "botId": BOT, "botVersion": "DRAFT"}}, "fileFormat": "LexJson"},
              {"exportId": EXPORT, "exportStatus": "InProgress"}),
        event("DescribeExport", 5, {"exportId": EXPORT}, read=True),
        event("DeleteExport", 6, {"exportId": EXPORT}, {"exportStatus": "Deleting"}),
        event("DeleteUtterances", 7, {"botId": BOT, "localeId": "en_US",
                                      "sessionId": "synthetic-session"}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_seven_observed_lex_management_routes_match():
    findings = hits(sample())
    assert len(findings) == 7
    assert {f.technique_id for f in findings} == IDS
    assert {f.target_id for f in findings} == {BOT, EXPORT}


def test_failed_and_malformed_lex_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["requestParameters"]["aggregationDuration"]["relativeAggregationDuration"]["timeValue"] = 360
    rows[1]["errorCode"] = "AccessDeniedException"
    rows[2]["requestParameters"]["endDateTime"] = 0
    rows[3]["responseElements"]["exportId"] = "foreign"
    rows[4]["readOnly"] = False
    rows[5]["eventSource"] = "other.amazonaws.com"
    rows[6]["requestParameters"].pop("sessionId")
    assert hits(rows) == []


def test_export_and_session_details_are_not_emitted():
    findings = hits(sample())
    assert "synthetic-session" not in str(findings)
    assert "TSTALIASID" not in str(findings)
    assert "Completion and download require separate checks" in next(
        f.description for f in findings if f.technique_id.endswith("bot-model-export-created"))
