"""Uploaded service-account keys require a completed IAM Admin Activity result."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp import normalize_gcp_audit, normalize_gcp_uploaded_service_account_key


PROJECT = "customer-project"
EMAIL = f"workload@{PROJECT}.iam.gserviceaccount.com"
KEY = f"projects/{PROJECT}/serviceAccounts/{EMAIL}/keys/abc123def456"


def event():
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "upload-event", "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "service_account", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.UploadServiceAccountKey",
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "resourceName": "projects/-/serviceAccounts/123456789012345678901",
            "request": {
                "@type": "type.googleapis.com/google.iam.admin.v1.UploadServiceAccountKeyRequest",
                "name": f"projects/-/serviceAccounts/{EMAIL}",
                "publicKeyData": "sensitive-public-key-material",
            },
            "response": {
                "@type": "type.googleapis.com/google.iam.admin.v1.ServiceAccountKey",
                "name": KEY, "keyOrigin": "USER_PROVIDED",
                "publicKeyData": "sensitive-public-key-material",
                "privateKeyData": "unexpected-sensitive-data",
            },
        },
    }


def test_upload_candidate_has_only_resource_evidence_and_no_key_material():
    row = event()
    result = normalize_gcp_uploaded_service_account_key(row)
    assert result == {
        "cloud.provider": "gcp", "event.name": "google.iam.admin.v1.UploadServiceAccountKey",
        "event.source": "iam.googleapis.com", "event.outcome": "success",
        "event.id": "upload-event", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "admin@example.com",
        "target.id": f"projects/-/serviceAccounts/{EMAIL}",
        "credential.key_name": KEY, "credential.key_origin": "USER_PROVIDED",
        "credential.upload_observed": True,
    }
    assert normalize_gcp_audit(row) == result
    assert "sensitive-" not in repr(result)
    assert "misuse" not in repr(result) and "compromise" not in repr(result)


def test_explicit_project_request_and_dash_return_are_accepted():
    row = event()
    row["protoPayload"]["request"]["name"] = f"projects/{PROJECT}/serviceAccounts/{EMAIL}"
    row["protoPayload"]["response"]["name"] = f"projects/-/serviceAccounts/{EMAIL}/keys/key-123"
    assert normalize_gcp_uploaded_service_account_key(row)["credential.key_name"].endswith("/keys/key-123")


@pytest.mark.parametrize("change", [
    "wrong_method", "wrong_service", "data_access", "wrong_resource_type", "foreign_project_label",
    "failed", "boolean_status", "floating_status", "missing_request", "redacted_request", "foreign_request_project",
    "foreign_request_email", "missing_response", "missing_key_name", "foreign_returned_email",
    "foreign_returned_project", "redacted_response", "wrong_key_origin", "missing_actor",
    "missing_event_id", "other_named_resource",
])
def test_incomplete_or_foreign_upload_cannot_be_a_candidate(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    if change == "wrong_method":
        payload["methodName"] = "google.iam.admin.v1.CreateServiceAccountKey"
    elif change == "wrong_service":
        payload["serviceName"] = "storage.googleapis.com"
    elif change == "data_access":
        row["logName"] = row["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_resource_type":
        row["resource"]["type"] = "project"
    elif change == "foreign_project_label":
        row["resource"]["labels"]["project_id"] = "other-project"
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "boolean_status":
        payload["status"] = {"code": False}
    elif change == "floating_status":
        payload["status"] = {"code": 0.0}
    elif change == "missing_request":
        payload.pop("request")
    elif change == "redacted_request":
        payload["request"]["name"] = "REDACTED"
    elif change == "foreign_request_project":
        payload["request"]["name"] = payload["request"]["name"].replace("projects/-", "projects/other-project")
    elif change == "foreign_request_email":
        payload["request"]["name"] = payload["request"]["name"].replace(PROJECT, "other-project")
    elif change == "missing_response":
        payload.pop("response")
    elif change == "missing_key_name":
        payload["response"].pop("name")
    elif change == "foreign_returned_email":
        payload["response"]["name"] = KEY.replace(PROJECT, "other-project")
    elif change == "foreign_returned_project":
        payload["response"]["name"] = KEY.replace(f"projects/{PROJECT}/", "projects/other-project/")
    elif change == "redacted_response":
        payload["response"]["name"] = "REDACTED"
    elif change == "wrong_key_origin":
        payload["response"]["keyOrigin"] = "GOOGLE_PROVIDED"
    elif change == "missing_actor":
        payload["authenticationInfo"] = {}
    elif change == "missing_event_id":
        row.pop("insertId")
    elif change == "other_named_resource":
        payload["resourceName"] = "projects/-/serviceAccounts/other@example.com"
    assert normalize_gcp_uploaded_service_account_key(row) is None
    if change != "wrong_method":
        assert normalize_gcp_audit(row) is None
