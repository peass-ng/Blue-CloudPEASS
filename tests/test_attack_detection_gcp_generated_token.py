"""Token issuance observations require explicit success and exact actor/target."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp import normalize_gcp_audit, normalize_gcp_generated_access_token


PROJECT = "customer-project"
SA = f"workload@{PROJECT}.iam.gserviceaccount.com"
TARGET = f"projects/-/serviceAccounts/{SA}"


def event():
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access",
        "insertId": "mint-event", "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "service_account", "labels": {
            "project_id": PROJECT, "email_id": SA, "unique_id": "123456789012345678901"}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iamcredentials.googleapis.com",
            "methodName": "GenerateAccessToken",
            "status": {"code": 0},
            "authenticationInfo": {"principalEmail": "operator@example.com"},
            "request": {"@type": "type.googleapis.com/google.iam.credentials.v1.GenerateAccessTokenRequest",
                        "name": TARGET, "scope": ["https://www.googleapis.com/auth/cloud-platform"]},
            "resourceName": f"projects/-/serviceAccounts/{SA}",
            "response": {"accessToken": "sensitive-access-token", "expireTime": "2026-10-18T13:00:00Z"},
        },
    }


def test_confirmed_cross_principal_mint_exposes_only_safe_fields():
    row = event()
    result = normalize_gcp_generated_access_token(row)
    assert result == {
        "cloud.provider": "gcp", "event.name": "GenerateAccessToken",
        "event.source": "iamcredentials.googleapis.com", "event.outcome": "success",
        "event.id": "mint-event", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "operator@example.com",
        "target.id": TARGET, "target.service_account": SA,
        "request.cross_principal": True, "credential.token_mint_observed": True,
    }
    assert normalize_gcp_audit(row) == result
    assert "sensitive-access-token" not in repr(result)
    assert "compromise" not in repr(result)


@pytest.mark.parametrize("change", [
    "admin_activity", "wrong_method", "wrong_service", "wrong_resource", "foreign_project",
    "foreign_email", "status_missing", "status_failed", "status_boolean", "status_float", "missing_request",
    "request_redacted", "request_other_sa", "request_wrong_type", "actor_missing", "actor_self",
    "named_resource_other", "start_only", "missing_event_id",
])
def test_incomplete_or_mismatched_mint_is_not_observed(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    if change == "admin_activity":
        row["logName"] = row["logName"].replace("%2Fdata_access", "%2Factivity")
    elif change == "wrong_method":
        payload["methodName"] = "GenerateIdToken"
    elif change == "wrong_service":
        payload["serviceName"] = "iam.googleapis.com"
    elif change == "wrong_resource":
        row["resource"]["type"] = "project"
    elif change == "foreign_project":
        row["resource"]["labels"]["project_id"] = "other-project"
    elif change == "foreign_email":
        row["resource"]["labels"]["email_id"] = SA.replace(PROJECT, "other-project")
    elif change == "status_missing":
        payload.pop("status")
    elif change == "status_failed":
        payload["status"]["code"] = 7
    elif change == "status_boolean":
        payload["status"]["code"] = False
    elif change == "status_float":
        payload["status"]["code"] = 0.0
    elif change == "missing_request":
        payload.pop("request")
    elif change == "request_redacted":
        payload["request"]["name"] = "REDACTED"
    elif change == "request_other_sa":
        payload["request"]["name"] = TARGET.replace("workload@", "other@")
    elif change == "request_wrong_type":
        payload["request"]["@type"] = "type.googleapis.com/google.iam.credentials.v1.GenerateIdTokenRequest"
    elif change == "actor_missing":
        payload["authenticationInfo"] = {}
    elif change == "actor_self":
        payload["authenticationInfo"]["principalEmail"] = SA
    elif change == "named_resource_other":
        payload["resourceName"] = f"projects/-/serviceAccounts/other@{PROJECT}.iam.gserviceaccount.com"
    elif change == "start_only":
        row["operation"] = {"first": True, "last": False}
    elif change == "missing_event_id":
        row.pop("insertId")
    assert normalize_gcp_generated_access_token(row) is None
    assert normalize_gcp_audit(row) is None


def test_numeric_resource_name_must_match_monitored_unique_id():
    row = event()
    row["protoPayload"]["resourceName"] = "projects/-/serviceAccounts/123456789012345678901"
    assert normalize_gcp_generated_access_token(row)["credential.token_mint_observed"] is True
    row["protoPayload"]["resourceName"] = "projects/-/serviceAccounts/987654321098765432109"
    assert normalize_gcp_generated_access_token(row) is None
