"""Synthetic derivatives of an isolated Lex role and Lambda-hook lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
BOT = "SYNTHBOT01"
OTHER_BOT = "SYNTHBOT02"
ALIAS = "SYNTHALIAS"
ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/synthetic-lex-a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/synthetic-lex-b"
FUNCTION = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:synthetic-hook"
IDS = {
    "aws-lex-v2-bot-service-role-selected",
    "aws-lex-v2-bot-service-role-updated",
    "aws-lex-v2-intent-fulfillment-hook-enabled",
    "aws-lex-v2-bot-model-version-deployed",
    "aws-lex-v2-bot-alias-hook-attached",
    "aws-lex-v2-role-backed-hook-configured",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
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
    alias_settings = {"en_US": {"enabled": True,
        "codeHookSpecification": {"lambdaCodeHook": {
            "codeHookInterfaceVersion": "1.0", "lambdaARN": FUNCTION}}}}
    return [
        event("CreateBot", 0, {"botName": "synthetic-bot", "roleArn": ROLE_A},
              {"botId": BOT, "roleArn": ROLE_A}),
        event("UpdateBot", 1, {"botId": BOT, "botName": "synthetic-bot", "roleArn": ROLE_B},
              {"botId": BOT, "roleArn": ROLE_B}),
        event("CreateIntent", 2, {"botId": BOT, "botVersion": "DRAFT",
                                  "localeId": "en_US", "intentName": "SyntheticHello",
                                  "sampleUtterances": [{"utterance": "synthetic hello"}],
                                  "fulfillmentCodeHook": {"enabled": True, "active": True}},
              {"botId": BOT, "intentId": "SYNTHINT01"}),
        event("CreateBotVersion", 3, {"botId": BOT,
                                      "botVersionLocaleSpecification": {
                                          "en_US": {"sourceBotVersion": "DRAFT"}}},
              {"botId": BOT, "botVersion": "1"}),
        event("UpdateBotAlias", 4, {"botId": BOT, "botAliasId": ALIAS,
                                    "botVersion": "1", "botAliasName": "SyntheticLiveAlias",
                                    "botAliasLocaleSettings": alias_settings},
              {"botId": BOT, "botAliasId": ALIAS}),
        event("CreateBot", 5, {"botName": "synthetic-extra", "roleArn": ROLE_B},
              {"botId": OTHER_BOT, "roleArn": ROLE_B}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_observed_role_and_hook_setup_matches_six_rules():
    findings = hits(sample())
    assert len(findings) == 7
    assert {finding.technique_id for finding in findings} == IDS
    correlated = [f for f in findings if f.technique_id == "aws-lex-v2-role-backed-hook-configured"]
    assert len(correlated) == 1
    assert correlated[0].target_id == BOT


def test_denials_and_incomplete_hook_configurations_fail_closed():
    rows = deepcopy(sample())
    rows[0]["errorCode"] = "AccessDeniedException"
    rows[1]["responseElements"]["roleArn"] = ROLE_A
    rows[2]["requestParameters"]["fulfillmentCodeHook"]["active"] = False
    rows[3]["requestParameters"]["botVersionLocaleSpecification"]["en_US"]["sourceBotVersion"] = "1"
    rows[4]["requestParameters"]["botAliasLocaleSettings"]["en_US"]["enabled"] = False
    rows[5]["errorCode"] = "AccessDeniedException"
    assert hits(rows) == []


def test_role_hook_correlation_requires_same_bot_account_and_order():
    rows = sample()
    rows[4]["requestParameters"]["botId"] = OTHER_BOT
    rows[4]["responseElements"]["botId"] = OTHER_BOT
    assert not any(f.technique_id == "aws-lex-v2-role-backed-hook-configured" for f in hits(rows))
    rows = sample()
    rows[4]["eventTime"] = "2026-10-21T11:59:00Z"
    assert not any(f.technique_id == "aws-lex-v2-role-backed-hook-configured" for f in hits(rows))
    rows = sample()
    rows[4]["recipientAccountId"] = "888888888888"
    assert not any(f.technique_id == "aws-lex-v2-role-backed-hook-configured" for f in hits(rows))


def test_role_lambda_and_utterance_details_are_not_emitted():
    output = str(hits(sample()))
    assert ROLE_A not in output
    assert ROLE_B not in output
    assert FUNCTION not in output
    assert "synthetic hello" not in output
