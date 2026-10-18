"""A completed console credential creation must identify another IAM user."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_login_profile_next import (
    normalize_aws_other_user_login_profile,
    normalize_aws_other_user_login_profile_update,
)


RULE = Rule(
    id="test-other-user-login-profile", title="Console password created for another user",
    level="medium", description="Successful IAM CreateLoginProfile without forced reset",
    technique_id="aws-iam-createloginprofile-other-user", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "CreateLoginProfile",
               "event.outcome": "success", "request.other_user": True,
               "request.password_reset_required": False,
               "response.login_profile_matches_target": True},
)
UPDATE_RULE = Rule(
    id="test-other-user-login-profile-update", title="Another user's login profile updated",
    level="low", description="Successful IAM UpdateLoginProfile without forced reset; password change is unproven",
    technique_id="aws-iam-updateloginprofile-other-user", product="aws",
    selection={"event.source": "iam.amazonaws.com", "event.name": "UpdateLoginProfile",
               "event.outcome": "success", "request.other_user": True,
               "request.password_reset_required": False, "request.profile_update_observed": True},
)


def event() -> dict:
    return {
        "eventSource": "iam.amazonaws.com", "eventName": "CreateLoginProfile",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "event-123", "eventTime": "2026-10-18T10:00:00Z",
        "recipientAccountId": "123456789012", "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012", "userName": "alice",
                         "arn": "arn:aws:iam::123456789012:user/team/alice"},
        "requestParameters": {"userName": "bob", "passwordResetRequired": False,
                              "password": "HIDDEN_DUE_TO_SECURITY_REASONS"},
        "responseElements": {"loginProfile": {"userName": "bob", "passwordResetRequired": False,
                                              "createDate": "2026-10-18T10:00:00Z"}},
    }


def test_exact_successful_creation_exposes_no_password() -> None:
    row = event()
    normalized = normalize_aws_other_user_login_profile(row)
    assert normalized is not None
    assert normalized["target.id"] == "iam-user:123456789012:bob"
    assert normalized["actor.id"] == row["userIdentity"]["arn"]
    assert row["requestParameters"]["password"] not in str(normalized)
    matches = detect_aws_events([row], [RULE])
    assert [item.rule_id for item in matches] == [RULE.id]
    assert matches[0].target_id == normalized["target.id"]


def test_same_account_assumed_role_can_create_other_user_profile() -> None:
    row = event()
    row["userIdentity"] = {
        "type": "AssumedRole", "accountId": "123456789012",
        "arn": "arn:aws:sts::123456789012:assumed-role/HelpDesk/session-1",
        "sessionContext": {"sessionIssuer": {
            "type": "Role", "accountId": "123456789012",
            "arn": "arn:aws:iam::123456789012:role/team/HelpDesk",
        }},
    }
    assert normalize_aws_other_user_login_profile(row)["actor.kind"] == "AssumedRole"
    assert [hit.rule_id for hit in detect_aws_events([row], [RULE])] == [RULE.id]
    row["userIdentity"]["sessionContext"]["sessionIssuer"]["arn"] = (
        "arn:aws:iam::999999999999:role/team/HelpDesk"
    )
    assert normalize_aws_other_user_login_profile(row) is None


def test_profile_update_matches_redacted_cloudtrail_shape_without_password_claim() -> None:
    row = event()
    row["eventName"] = "UpdateLoginProfile"
    row["responseElements"] = None
    row["requestParameters"].pop("password")
    normalized = normalize_aws_other_user_login_profile_update(row)
    assert normalized is not None
    assert normalized["request.profile_update_observed"] is True
    assert "password_field_present" not in normalized
    assert [hit.rule_id for hit in detect_aws_events([row], [UPDATE_RULE])] == [UPDATE_RULE.id]


@pytest.mark.parametrize("change", [
    "reset_required", "same_user", "missing_response",
    "denied", "wrong_action", "foreign_account", "bad_actor", "read_only",
])
def test_password_update_without_required_evidence_is_rejected(change: str) -> None:
    row = event()
    row["eventName"] = "UpdateLoginProfile"
    row["responseElements"] = None
    request = row["requestParameters"]
    if change == "reset_required": request["passwordResetRequired"] = True
    if change == "same_user": request["userName"] = "alice"
    if change == "missing_response": row.pop("responseElements")
    if change == "denied": row["errorCode"] = "AccessDenied"
    if change == "wrong_action": row["eventName"] = "CreateLoginProfile"
    if change == "foreign_account": row["recipientAccountId"] = "999999999999"
    if change == "bad_actor": row["userIdentity"]["arn"] = "unverified"
    if change == "read_only": row["readOnly"] = True
    assert normalize_aws_other_user_login_profile_update(row) is None
    assert detect_aws_events([row], [UPDATE_RULE]) == []


@pytest.mark.parametrize("change", [
    "same_user", "reset_required", "missing_reset", "string_false", "response_reset_required",
    "response_user", "missing_response", "missing_profile", "missing_create_date",
    "invalid_create_date", "denied", "response_error", "wrong_source", "wrong_action",
    "not_management", "read_only", "missing_event_id", "invalid_event_time",
    "foreign_account", "foreign_actor", "actor_name_mismatch", "missing_actor",
    "assumed_role", "bad_target", "missing_target", "bad_actor_path",
])
def test_incomplete_or_different_credential_change_rejected(change: str) -> None:
    row = deepcopy(event())
    request, response, identity = row["requestParameters"], row["responseElements"], row["userIdentity"]
    if change == "same_user": request["userName"] = response["loginProfile"]["userName"] = "alice"
    if change == "reset_required": request["passwordResetRequired"] = True
    if change == "missing_reset": request.pop("passwordResetRequired")
    if change == "string_false": request["passwordResetRequired"] = "false"
    if change == "response_reset_required": response["loginProfile"]["passwordResetRequired"] = True
    if change == "response_user": response["loginProfile"]["userName"] = "carol"
    if change == "missing_response": row.pop("responseElements")
    if change == "missing_profile": response.pop("loginProfile")
    if change == "missing_create_date": response["loginProfile"].pop("createDate")
    if change == "invalid_create_date": response["loginProfile"]["createDate"] = "yesterday"
    if change == "denied": row["errorCode"] = "AccessDenied"
    if change == "response_error": response["errorMessage"] = "failed"
    if change == "wrong_source": row["eventSource"] = "sts.amazonaws.com"
    if change == "wrong_action": row["eventName"] = "UpdateLoginProfile"
    if change == "not_management": row["eventCategory"] = "Data"
    if change == "read_only": row["readOnly"] = True
    if change == "missing_event_id": row.pop("eventID")
    if change == "invalid_event_time": row["eventTime"] = "not-a-time"
    if change == "foreign_account": row["recipientAccountId"] = "999999999999"
    if change == "foreign_actor": identity["accountId"] = "999999999999"
    if change == "actor_name_mismatch": identity["userName"] = "eve"
    if change == "missing_actor": identity.pop("arn")
    if change == "assumed_role": identity["type"] = "AssumedRole"
    if change == "bad_target": request["userName"] = "bad/user"
    if change == "missing_target": request.pop("userName")
    if change == "bad_actor_path": identity["arn"] = "arn:aws:iam::123456789012:user/team//alice"
    assert normalize_aws_other_user_login_profile(row) is None
    assert detect_aws_events([row], [RULE]) == []
