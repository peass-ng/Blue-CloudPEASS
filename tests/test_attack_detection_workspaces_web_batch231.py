"""WorkSpaces Web control changes require confirmed request and response state."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"


def _event(name: str, kind: str):
    arn = f"arn:aws:workspaces-web:{REGION}:{ACCOUNT}:{kind}/synthetic-resource"
    arn_key = kind[0].lower() + kind[1:] + "Arn"
    return {
        "eventSource": "workspaces-web.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "synthetic-event", "eventTime": "2026-10-22T04:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {arn_key: arn, "clientToken": "private-token"},
        "responseElements": {kind: {arn_key: arn}},
    }


def _rules(directory: Path):
    for suffix, name, field in (
        ("redaction", "UpdateDataProtectionSettings",
         "request.workspaces_web_redaction_patterns_empty"),
        ("transfer", "UpdateUserSettings", "request.workspaces_web_transfer_enabled"),
    ):
        (directory / f"{suffix}.yml").write_text(f"""title: Synthetic WorkSpaces Web {suffix}
id: 23100000-0000-4000-8000-00000000000{1 if suffix == 'redaction' else 2}
status: experimental
description: Synthetic test rule.
references: [https://example.test/workspaces-web]
logsource: {{product: aws, service: cloudtrail}}
detection:
  selection:
    event.source: workspaces-web.amazonaws.com
    event.name: {name}
    event.outcome: success
    {field}: true
  condition: selection
falsepositives: [Approved configuration]
level: medium
x_hacktricks_technique_id: synthetic-workspaces-web-{suffix}
""", encoding="utf-8")
    return load_rules(directory, product="aws")


def test_empty_redaction_patterns_are_confirmed_without_leaking_settings(tmp_path):
    selected = _rules(tmp_path)
    item = _event("UpdateDataProtectionSettings", "dataProtectionSettings")
    item["requestParameters"]["inlineRedactionConfiguration"] = {
        "inlineRedactionPatterns": [], "globalExemptUrls": ["private.example.test"]}
    item["responseElements"]["dataProtectionSettings"]["inlineRedactionConfiguration"] = {
        "inlineRedactionPatterns": []}
    hits = detect_aws_events([item], selected)
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert "private.example.test" not in str(hits)
    request_has_patterns = deepcopy(item)
    request_has_patterns["requestParameters"]["inlineRedactionConfiguration"][
        "inlineRedactionPatterns"] = [{}]
    response_has_patterns = deepcopy(item)
    response_has_patterns["responseElements"]["dataProtectionSettings"][
        "inlineRedactionConfiguration"]["inlineRedactionPatterns"] = [{}]
    denied = deepcopy(item); denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events(
        [request_has_patterns, response_has_patterns, denied], selected) == []


def test_transfer_enablement_requires_matching_returned_setting(tmp_path):
    selected = _rules(tmp_path)
    item = _event("UpdateUserSettings", "userSettings")
    item["requestParameters"]["downloadAllowed"] = "Enabled"
    item["responseElements"]["userSettings"]["downloadAllowed"] = "Enabled"
    assert len(detect_aws_events([item], selected)) == 1
    for key, value in (("downloadAllowed", "Disabled"), ("downloadAllowed", None)):
        rejected = deepcopy(item)
        if value is None:
            rejected["responseElements"]["userSettings"].pop(key)
        else:
            rejected["responseElements"]["userSettings"][key] = value
        assert detect_aws_events([rejected], selected) == []
    for key, value in (("readOnly", True), ("eventCategory", "Data"),
                       ("errorCode", "ValidationException")):
        rejected = deepcopy(item); rejected[key] = value
        assert detect_aws_events([rejected], selected) == []
