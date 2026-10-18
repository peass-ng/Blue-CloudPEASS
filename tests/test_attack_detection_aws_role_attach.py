"""Synthetic evidence cases for the self-role managed-policy attachment signal."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events, normalize_aws_cloudtrail


ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
RULE = Rule(
    id="synthetic-attach-role", title="Observed self-role policy attachment", level="high",
    description="A completed attachment operation; effective access and intent are not inferred.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "AttachRolePolicy",
               "event.outcome": "success", "actor.kind": "AssumedRole",
               "request.self_role_admin_policy_attach": True},
)


def role_attachment() -> dict:
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "AttachRolePolicy",
        "eventID": "attach-role-1", "eventTime": "2026-10-18T00:00:00Z",
        "recipientAccountId": "123456789012", "responseElements": None,
        "requestParameters": {"roleName": "Workload", "policyArn": ADMINISTRATOR_ACCESS_ARN},
        "userIdentity": {
            "type": "AssumedRole", "accountId": "123456789012",
            "arn": "arn:aws:sts::123456789012:assumed-role/Workload/session-1",
            "sessionContext": {"sessionIssuer": {
                "type": "Role", "userName": "Workload",
                "arn": "arn:aws:iam::123456789012:role/Workload",
            }},
        },
    }


def test_successful_exact_attachment_to_issuing_role_is_observed() -> None:
    event = role_attachment()
    normalized = normalize_aws_cloudtrail(event)
    assert normalized["request.self_role"] is True
    assert normalized["request.self_role_admin_policy_attach"] is True
    assert normalized["request.policy_arn"] == ADMINISTRATOR_ACCESS_ARN
    assert normalized["target.id"] == "Workload"
    matches = detect_aws_events([event], [RULE])
    assert len(matches) == 1
    assert matches[0].actor_id == event["userIdentity"]["arn"]
    assert matches[0].target_id == "Workload"
    assert matches[0].event_id == "attach-role-1"


def test_issuing_role_path_does_not_hide_a_matching_attachment() -> None:
    event = role_attachment()
    event["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
        "arn:aws:iam::123456789012:role/team/Workload"
    )
    assert len(detect_aws_events([event], [RULE])) == 1


def test_denied_foreign_malformed_and_incomplete_events_do_not_match() -> None:
    good = role_attachment()
    negatives = []
    for edit in (
        "denied", "error_message", "response_error", "wrong_action", "wrong_source",
        "different_role", "different_issuer_name", "different_issuer_arn", "different_session_role",
        "recipient_account_mismatch", "missing_recipient_account", "identity_account_mismatch",
        "issuer_account_mismatch", "issuer_account_field_mismatch",
        "different_partition", "regional_issuer_arn", "missing_target", "missing_policy",
        "wrong_policy", "missing_issuer",
        "iam_user", "empty_session", "malformed_session", "malformed_issuer_arn",
    ):
        row = deepcopy(good)
        request = row["requestParameters"]
        identity = row["userIdentity"]
        issuer = identity["sessionContext"]["sessionIssuer"]
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "error_message": row["errorMessage"] = "Access denied"
        if edit == "response_error": row["responseElements"] = {"errorCode": "AccessDenied"}
        if edit == "wrong_action": row["eventName"] = "DetachRolePolicy"
        if edit == "wrong_source": row["eventSource"] = "sts.amazonaws.com"
        if edit == "different_role": request["roleName"] = "OtherRole"
        if edit == "different_issuer_name": issuer["userName"] = "OtherRole"
        if edit == "different_issuer_arn": issuer["arn"] = "arn:aws:iam::123456789012:role/OtherRole"
        if edit == "different_session_role": identity["arn"] = "arn:aws:sts::123456789012:assumed-role/OtherRole/session-1"
        if edit == "recipient_account_mismatch": row["recipientAccountId"] = "999999999999"
        if edit == "missing_recipient_account": row.pop("recipientAccountId")
        if edit == "identity_account_mismatch": identity["accountId"] = "999999999999"
        if edit == "issuer_account_mismatch": issuer["arn"] = "arn:aws:iam::999999999999:role/Workload"
        if edit == "issuer_account_field_mismatch": issuer["accountId"] = "999999999999"
        if edit == "different_partition": identity["arn"] = "arn:aws-us-gov:sts::123456789012:assumed-role/Workload/session-1"
        if edit == "regional_issuer_arn": issuer["arn"] = "arn:aws:iam:us-east-1:123456789012:role/Workload"
        if edit == "missing_target": request.pop("roleName")
        if edit == "missing_policy": request.pop("policyArn")
        if edit == "wrong_policy": request["policyArn"] = "arn:aws:iam::aws:policy/PowerUserAccess"
        if edit == "missing_issuer": identity["sessionContext"].pop("sessionIssuer")
        if edit == "iam_user": identity["type"] = "IAMUser"
        if edit == "empty_session": identity["arn"] = "arn:aws:sts::123456789012:assumed-role/Workload/"
        if edit == "malformed_session": identity["arn"] += "/extra"
        if edit == "malformed_issuer_arn": issuer["arn"] = "not-an-arn:aws:iam::123456789012:role/Workload"
        negatives.append(row)
    assert detect_aws_events(negatives, [RULE]) == []
    assert all(normalize_aws_cloudtrail(row) is None or
               normalize_aws_cloudtrail(row)["request.self_role_admin_policy_attach"] is False
               for row in negatives)
