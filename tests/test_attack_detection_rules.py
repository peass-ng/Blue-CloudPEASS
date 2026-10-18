"""Public, synthetic fixtures for the generic evaluator and AWS normalizer."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from peaso.attack_detection import Rule, detect_aws_events, load_rules, normalize_aws_cloudtrail


ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


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
    assert matches[0].event_time == "2026-10-18T00:00:00Z"
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


def test_self_attach_administrator_access_requires_exact_policy_and_success() -> None:
    rule = synthetic_rule({"event.name": "AttachUserPolicy", "event.outcome": "success",
                           "actor.kind": "IAMUser", "request.self_user": True,
                           "request.policy_arn": ADMIN_POLICY_ARN})
    good = event("AttachUserPolicy", {"userName": "alice", "policyArn": ADMIN_POLICY_ARN})
    assert len(detect_aws_events([good], [rule])) == 1
    negatives = [
        event("AttachUserPolicy", {"userName": "alice", "policyArn": ADMIN_POLICY_ARN}, error="AccessDenied"),
        event("AttachUserPolicy", {"userName": "bob", "policyArn": ADMIN_POLICY_ARN}),
        event("AttachUserPolicy", {"userName": "alice", "policyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}),
        event("AttachUserPolicy", {"userName": "alice"}),
    ]
    assert detect_aws_events(negatives, [rule]) == []


def test_assumed_role_self_put_role_policy_requires_issuer_and_unconditional_grant() -> None:
    rule = synthetic_rule({"event.name": "PutRolePolicy", "event.outcome": "success",
                           "actor.kind": "AssumedRole", "request.self_role": True,
                           "request.unconditional_admin_grant": True})
    good = event("PutRolePolicy", {"roleName": "AppRole", "policyName": "Admin",
                                   "policyDocument": quote(json.dumps(ADMIN))})
    good["userIdentity"] = {
        "type": "AssumedRole", "accountId": "123456789012",
        "arn": "arn:aws:sts::123456789012:assumed-role/AppRole/session-a",
        "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "AppRole",
                                             "arn": "arn:aws:iam::123456789012:role/AppRole"}},
    }
    assert normalize_aws_cloudtrail(good)["request.self_role"] is True
    assert len(detect_aws_events([good], [rule])) == 1
    path_role = json.loads(json.dumps(good))
    path_role["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = "arn:aws:iam::123456789012:role/team/AppRole"
    assert len(detect_aws_events([path_role], [rule])) == 1
    negatives = []
    for edit in ("denied", "other_role", "other_session", "other_account", "identity_account_mismatch",
                 "missing_issuer", "conditional", "explicit_deny", "malformed", "narrow_action", "incomplete_target"):
        row = json.loads(json.dumps(good))
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "other_role": row["requestParameters"]["roleName"] = "OtherRole"
        if edit == "other_session": row["userIdentity"]["arn"] = "arn:aws:sts::123456789012:assumed-role/OtherRole/session-a"
        if edit == "other_account": row["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = "arn:aws:iam::999999999999:role/AppRole"
        if edit == "identity_account_mismatch": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_issuer": row["userIdentity"].pop("sessionContext")
        if edit == "conditional": row["requestParameters"]["policyDocument"] = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]})
        if edit == "explicit_deny": row["requestParameters"]["policyDocument"] = json.dumps({"Statement": [ADMIN["Statement"][0], {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]})
        if edit == "malformed": row["requestParameters"]["policyDocument"] = "not-json"
        if edit == "narrow_action": row["requestParameters"]["policyDocument"] = json.dumps({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})
        if edit == "incomplete_target": row["requestParameters"].pop("roleName")
        negatives.append(row)
    assert detect_aws_events(negatives, [rule]) == []
