"""Public, synthetic fixtures for the generic evaluator and AWS normalizer."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from peaso.attack_detection import Rule, detect_aws_events, load_rules, normalize_aws_cloudtrail


ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def event(name: str, request: dict, *, user: str = "alice", error: str | None = None) -> dict:
    record = {
        "eventSource": "iam.amazonaws.com",
        "eventName": name,
        "eventID": "event-123",
        "eventTime": "2026-10-18T00:00:00Z",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::123456789012:user/{user}"},
        "requestParameters": request,
        "responseElements": None,
    }
    if error:
        record["errorCode"] = error
    return record


def synthetic_rule(selection: dict) -> Rule:
    return Rule(id="unit-test", title="Synthetic example", level="low", description="Test only",
                technique_id="synthetic", product="aws", selection=selection)


def test_loads_synthetic_sigma_subset_from_explicit_directory(tmp_path) -> None:
    (tmp_path / "unit.yml").write_text(
        "id: unit-test\ntitle: Synthetic example\nlevel: low\ndescription: Test only\n"
        "x_hacktricks_technique_id: synthetic\nlogsource: {product: aws, service: cloudtrail}\n"
        "detection:\n  selection:\n    event.outcome: success\n    event.name: [ExampleOne, ExampleTwo]\n"
        "  condition: selection\n", encoding="utf-8")
    rules = load_rules(tmp_path, product="aws")
    assert len(rules) == 1
    assert rules[0].selection["event.name"] == ["ExampleOne", "ExampleTwo"]


def test_self_admin_inline_policy_and_negative_cases() -> None:
    request = {"userName": "alice", "policyName": "Admin", "policyDocument": quote(json.dumps(ADMIN))}
    good = event("PutUserPolicy", request)
    rules = [synthetic_rule({"event.outcome": "success", "request.unconditional_admin_grant": True})]
    matches = detect_aws_events([good], rules)
    assert len(matches) == 1
    assert matches[0].target_id == "alice"
    assert matches[0].evidence["request.unconditional_admin_grant"] is True

    narrower = {**ADMIN, "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
    negatives = [
        event("PutUserPolicy", request, error="AccessDenied"),
        event("PutUserPolicy", {**request, "policyDocument": json.dumps(narrower)}),
        event("PutUserPolicy", {**request, "policyDocument": "malformed"}),
        event("PutUserPolicy", {**request, "policyDocument": json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})}),
    ]
    assert detect_aws_events(negatives, rules) == []
    assert normalize_aws_cloudtrail(good)["request.self_user"] is True
    assert normalize_aws_cloudtrail(event("PutUserPolicy", {**request, "userName": "bob"}))["request.self_user"] is False


def test_default_policy_version_requires_default_and_admin_grant() -> None:
    request = {"policyArn": "arn:aws:iam::123456789012:policy/Example", "setAsDefault": True, "policyDocument": json.dumps(ADMIN)}
    good = normalize_aws_cloudtrail(event("CreatePolicyVersion", request))
    assert good["request.set_as_default"] is True
    assert good["request.unconditional_admin_grant"] is True
    negatives = [
        event("CreatePolicyVersion", {**request, "setAsDefault": False}),
        event("CreatePolicyVersion", request, error="MalformedPolicyDocument"),
        event("CreatePolicyVersion", {**request, "policyDocument": json.dumps({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})}),
    ]
    normalized = [normalize_aws_cloudtrail(row) for row in negatives]
    assert normalized[0]["request.set_as_default"] is False
    assert normalized[1]["event.outcome"] == "failure"
    assert normalized[2]["request.unconditional_admin_grant"] is False


def test_other_user_access_key_excludes_self_failed_and_non_iam_actor() -> None:
    record = event("CreateAccessKey", {"userName": "bob"})
    matches = detect_aws_events([record], [synthetic_rule({"request.other_user": True, "event.outcome": "success"})])
    assert len(matches) == 1
    assert matches[0].target_id == "bob"
    assumed = event("CreateAccessKey", {"userName": "bob"})
    assumed["userIdentity"] = {"type": "AssumedRole", "arn": "arn:aws:sts::123456789012:assumed-role/Admin/session"}
    negatives = [
        event("CreateAccessKey", {"userName": "alice"}),
        event("CreateAccessKey", {"userName": "bob"}, error="AccessDenied"),
        event("CreateAccessKey", {}),
        assumed,
    ]
    assert [normalize_aws_cloudtrail(row)["request.other_user"] for row in negatives] == [False, True, False, False]
    assert detect_aws_events(negatives, [synthetic_rule({"request.other_user": True, "event.outcome": "success"})]) == []


def test_non_iam_source_and_unsupported_sigma_grammar_fail_closed(tmp_path) -> None:
    record = event("CreateAccessKey", {"userName": "bob"})
    record["eventSource"] = "ec2.amazonaws.com"
    assert normalize_aws_cloudtrail(record) is None
    assert detect_aws_events([record], [synthetic_rule({"event.outcome": "success"})]) == []
    rule = tmp_path / "bad.yml"
    rule.write_text("id: bad\ntitle: Bad\nlevel: high\ndescription: Bad\nx_hacktricks_technique_id: bad\nlogsource: {product: aws, service: cloudtrail}\ndetection: {selection: {event.name|contains: Policy}, condition: selection}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Unsupported detection selection"):
        load_rules(tmp_path)
