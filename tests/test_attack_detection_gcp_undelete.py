"""A service-account restore candidate needs matching request and response IDs."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp import normalize_gcp_audit, normalize_gcp_undeleted_service_account


PROJECT = "customer-project"
UNIQUE_ID = "123456789012345678901"
EMAIL = f"workload@{PROJECT}.iam.gserviceaccount.com"


def event():
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "restore-event", "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "service_account", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.UndeleteServiceAccount",
            "authenticationInfo": {"principalEmail": "owner@example.com"},
            "resourceName": f"projects/-/serviceAccounts/{UNIQUE_ID}",
            "request": {
                "@type": "type.googleapis.com/google.iam.admin.v1.UndeleteServiceAccountRequest",
                "name": f"projects/-/serviceAccounts/{UNIQUE_ID}",
            },
            "response": {
                "@type": "type.googleapis.com/google.iam.admin.v1.UndeleteServiceAccountResponse",
                "restoredAccount": {
                    "name": f"projects/{PROJECT}/serviceAccounts/{EMAIL}",
                    "projectId": PROJECT, "uniqueId": UNIQUE_ID, "email": EMAIL,
                    "oauth2ClientId": "987654321098765432109",
                },
            },
        },
    }


def test_matching_restore_observes_identity_only():
    row = event()
    result = normalize_gcp_undeleted_service_account(row)
    assert result == {
        "cloud.provider": "gcp", "event.name": "google.iam.admin.v1.UndeleteServiceAccount",
        "event.source": "iam.googleapis.com", "event.outcome": "success",
        "event.id": "restore-event", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "owner@example.com",
        "target.id": f"projects/{PROJECT}/serviceAccounts/{EMAIL}",
        "target.service_account": EMAIL, "identity.unique_id": UNIQUE_ID,
        "identity.restore_observed": True,
    }
    assert normalize_gcp_audit(row) == result
    assert not any("permission" in field or "credential" in field for field in result)


@pytest.mark.parametrize("change", [
    "data_access", "wrong_method", "wrong_service", "wrong_resource_type", "foreign_resource_label",
    "failed", "boolean_status", "floating_status", "missing_request", "request_email", "foreign_request_project",
    "missing_response", "missing_restored_account", "redacted_response", "wrong_response_id",
    "wrong_response_project", "wrong_response_email", "wrong_response_name",
    "wrong_resource_name", "missing_actor", "missing_event_id",
])
def test_incomplete_or_mismatched_restore_is_not_confirmed(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    restored = payload["response"]["restoredAccount"]
    if change == "data_access":
        row["logName"] = row["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_method":
        payload["methodName"] = "google.iam.admin.v1.EnableServiceAccount"
    elif change == "wrong_service":
        payload["serviceName"] = "cloudresourcemanager.googleapis.com"
    elif change == "wrong_resource_type":
        row["resource"]["type"] = "project"
    elif change == "foreign_resource_label":
        row["resource"]["labels"]["project_id"] = "other-project"
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "boolean_status":
        payload["status"] = {"code": False}
    elif change == "floating_status":
        payload["status"] = {"code": 0.0}
    elif change == "missing_request":
        payload.pop("request")
    elif change == "request_email":
        payload["request"]["name"] = f"projects/-/serviceAccounts/{EMAIL}"
    elif change == "foreign_request_project":
        payload["request"]["name"] = f"projects/other-project/serviceAccounts/{UNIQUE_ID}"
    elif change == "missing_response":
        payload.pop("response")
    elif change == "missing_restored_account":
        payload["response"].pop("restoredAccount")
    elif change == "redacted_response":
        payload["response"]["restoredAccount"] = "REDACTED"
    elif change == "wrong_response_id":
        restored["uniqueId"] = "987654321098765432109"
    elif change == "wrong_response_project":
        restored["projectId"] = "other-project"
    elif change == "wrong_response_email":
        restored["email"] = "workload@other-project.iam.gserviceaccount.com"
    elif change == "wrong_response_name":
        restored["name"] = "projects/other-project/serviceAccounts/workload@other-project.iam.gserviceaccount.com"
    elif change == "wrong_resource_name":
        payload["resourceName"] = "projects/-/serviceAccounts/987654321098765432109"
    elif change == "missing_actor":
        payload["authenticationInfo"] = {}
    elif change == "missing_event_id":
        row.pop("insertId")
    assert normalize_gcp_undeleted_service_account(row) is None
    if change != "wrong_method":
        assert normalize_gcp_audit(row) is None


def test_exact_project_instead_of_dash_is_also_valid():
    row = event()
    row["protoPayload"]["request"]["name"] = f"projects/{PROJECT}/serviceAccounts/{UNIQUE_ID}"
    row["protoPayload"]["resourceName"] = f"projects/{PROJECT}/serviceAccounts/{UNIQUE_ID}"
    assert normalize_gcp_undeleted_service_account(row)["identity.unique_id"] == UNIQUE_ID
