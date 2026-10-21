"""Synthetic derivatives of own Lex V2 runtime CloudTrail data events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
BOT = "SYNTHBOT01"
ALIAS = "SYNTHALIAS"
TARGET = f"arn:aws:lex:{REGION}:{ACCOUNT}:bot-alias/{BOT}/{ALIAS}"
IDS = {
    "aws-lex-v2-runtime-text-recognized",
    "aws-lex-v2-runtime-utterance-recognized",
    "aws-lex-v2-runtime-session-read",
    "aws-lex-v2-runtime-session-changed",
    "aws-lex-v2-runtime-session-deleted",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 5
    return selected


def event(name, index, *, read=False):
    request = {"botId": BOT, "botAliasId": ALIAS, "localeId": "en_US",
               "sessionId": "synthetic-private-session"}
    if name == "RecognizeText":
        request["text"] = "synthetic hello"
    if name == "RecognizeUtterance":
        request.update(requestContentType="text/plain; charset=utf-8",
                       responseContentType="text/plain; charset=utf-8")
    if name == "PutSession":
        request["sessionState"] = {"sessionAttributes": {"workflowStage": "synthetic-approved"}}
    return {
        "eventSource": "lex.amazonaws.com", "eventName": name,
        "eventCategory": "Data", "eventType": "AwsApiCall",
        "managementEvent": False, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T12:00:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": None,
        "resources": [{"type": "AWS::Lex::BotAlias", "ARN": TARGET}],
    }


def sample():
    return [event("RecognizeText", 1), event("RecognizeUtterance", 2),
            event("GetSession", 3, read=True), event("PutSession", 4),
            event("DeleteSession", 5)]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_five_runtime_routes_match_only_successful_data_events():
    findings = hits(sample())
    assert len(findings) == 5
    assert {finding.technique_id for finding in findings} == IDS
    assert {finding.target_id for finding in findings} == {TARGET}


def test_errors_wrong_resource_and_management_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["errorCode"] = "ValidationException"
    rows[1]["requestParameters"]["requestContentType"] = "audio/l16; rate=16000; channels=1"
    rows[2]["resources"][0]["ARN"] += "-other"
    rows[3]["eventCategory"] = "Management"
    rows[4]["requestParameters"].pop("sessionId")
    assert hits(rows) == []


def test_runtime_output_discards_conversation_and_session_content():
    findings = hits(sample())
    output = str(findings)
    assert "synthetic-private-session" not in output
    assert "synthetic-approved" not in output
    assert "synthetic hello" not in output
