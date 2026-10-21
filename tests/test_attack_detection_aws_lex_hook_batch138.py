"""Synthetic derivatives of the owned Lex intent and alias-hook lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
BOT = "SYNTHBOT01"
ALIAS = "SYNTHALIAS"
INTENT = "SYNTHINT01"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-lex-service"
FUNCTION = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:synthetic-hook"
IDS = {
    "aws-lex-v2-intent-fulfillment-hook-updated",
    "aws-lex-v2-bot-alias-hook-created",
    "aws-lex-v2-role-backed-hook-configured",
}


def rules():
    selected = [r for r in load_rules(product="aws") if r.technique_id in IDS]
    assert len(selected) == 3
    return selected


def event(name, index, request, response):
    return {
        "eventSource": "lex.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T12:{index:02d}:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    settings = {"en_US": {"enabled": True,
        "codeHookSpecification": {"lambdaCodeHook": {
            "codeHookInterfaceVersion": "1.0", "lambdaARN": FUNCTION}}}}
    return [
        event("CreateBot", 0, {"botName": "synthetic-bot", "roleArn": ROLE},
              {"botId": BOT, "roleArn": ROLE}),
        event("CreateBotAlias", 1, {"botId": BOT, "botVersion": "1",
                                    "botAliasName": "synthetic-alias",
                                    "botAliasLocaleSettings": settings},
              {"botId": BOT, "botAliasId": ALIAS, "botVersion": "1",
               "botAliasLocaleSettings": deepcopy(settings)}),
        event("UpdateIntent", 2, {"botId": BOT, "botVersion": "DRAFT",
                                 "localeId": "en_US", "intentId": INTENT,
                                 "intentName": "SyntheticHello",
                                 "fulfillmentCodeHook": {"enabled": True, "active": True}},
              {"botId": BOT, "botVersion": "DRAFT", "intentId": INTENT,
               "fulfillmentCodeHook": {"enabled": True, "active": True}}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_observed_alias_creation_and_intent_update_match_three_rules():
    findings = hits(sample())
    assert len(findings) == 3
    assert {finding.technique_id for finding in findings} == IDS
    assert all(finding.target_id == BOT for finding in findings)


def test_disabled_intent_update_does_not_match():
    rows = sample()
    rows[2]["requestParameters"]["fulfillmentCodeHook"] = {"enabled": False, "active": False}
    rows[2]["responseElements"]["fulfillmentCodeHook"] = {"enabled": False, "active": False}
    assert not any(f.technique_id == "aws-lex-v2-intent-fulfillment-hook-updated" for f in hits(rows))


def test_inactive_or_unconfirmed_intent_update_does_not_match():
    rows = sample()
    rows[2]["requestParameters"]["fulfillmentCodeHook"]["active"] = False
    assert not any(f.technique_id == "aws-lex-v2-intent-fulfillment-hook-updated" for f in hits(rows))
    rows = sample()
    rows[2]["responseElements"]["fulfillmentCodeHook"]["enabled"] = False
    assert not any(f.technique_id == "aws-lex-v2-intent-fulfillment-hook-updated" for f in hits(rows))
    rows = sample()
    rows[2]["responseElements"]["intentId"] = "OTHERINT01"
    assert not any(f.technique_id == "aws-lex-v2-intent-fulfillment-hook-updated" for f in hits(rows))


def test_alias_without_confirmed_hook_does_not_match():
    rows = sample()
    rows[1]["requestParameters"]["botAliasLocaleSettings"]["en_US"]["enabled"] = False
    assert not any(f.technique_id == "aws-lex-v2-bot-alias-hook-created" for f in hits(rows))
    rows = sample()
    rows[1]["responseElements"]["botAliasLocaleSettings"] = {}
    assert not any(f.technique_id == "aws-lex-v2-bot-alias-hook-created" for f in hits(rows))


def test_denied_events_do_not_match_or_correlate():
    rows = sample()
    rows[0]["errorCode"] = "AccessDeniedException"
    rows[1]["errorCode"] = "AccessDeniedException"
    rows[2]["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []


def test_role_hook_correlation_needs_same_bot_and_one_hour():
    rows = sample()
    rows[1]["requestParameters"]["botId"] = "OTHERBOT01"
    rows[1]["responseElements"]["botId"] = "OTHERBOT01"
    assert not any(f.technique_id == "aws-lex-v2-role-backed-hook-configured" for f in hits(rows))
    rows = sample()
    rows[1]["eventTime"] = "2026-10-21T13:01:00Z"
    assert not any(f.technique_id == "aws-lex-v2-role-backed-hook-configured" for f in hits(rows))


def test_findings_omit_role_function_and_utterance():
    findings = str(hits(sample()))
    assert ROLE not in findings
    assert FUNCTION not in findings
    assert "synthetic hello" not in findings
