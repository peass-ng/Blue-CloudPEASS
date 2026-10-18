"""Cloud Storage HMAC creation needs returned key metadata and exact ownership."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp_hmac_next import normalize_gcp_hmac_key_created


PROJECT = "customer-project"
TARGET = f"backup@{PROJECT}.iam.gserviceaccount.com"
ACCESS_ID = "GOOGEXAMPLE123456"


def event() -> dict:
    # Shape checked against one sanitized live Admin Activity record. All
    # identifiers and the secret below are synthetic.
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {"type": "audited_resource", "labels": {"project_id": PROJECT}},
        "insertId": "hmac-created", "timestamp": "2026-10-18T12:00:00Z",
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "storage.googleapis.com", "methodName": "storage.hmacKeys.create",
            "resourceName": "projects/123456789012", "status": {},
            "authenticationInfo": {"principalEmail": "operator@example.com"},
            "request": {
                "@type": "type.googleapis.com/google.storage.v1.CreateHmacKeyRequest",
                "projectId": PROJECT, "serviceAccountEmail": TARGET,
            },
            "response": {
                "@type": "type.googleapis.com/google.storage.v1.CreateHmacKeyResponse",
                "metadata": {
                    "accessId": ACCESS_ID, "id": f"{PROJECT}/{ACCESS_ID}",
                    "projectId": PROJECT, "serviceAccountEmail": TARGET, "state": "ACTIVE",
                },
                "secret": "synthetic-secret-must-never-appear",
            },
        },
    }


def test_live_shaped_success_reports_only_observed_creation():
    result = normalize_gcp_hmac_key_created(event())
    assert result == {
        "cloud.provider": "gcp", "event.source": "storage.googleapis.com",
        "event.name": "storage.hmacKeys.create", "event.outcome": "success",
        "event.id": "hmac-created", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "operator@example.com",
        "target.id": f"projects/{PROJECT}/hmacKeys/{ACCESS_ID}",
        "target.service_account": TARGET,
        "credential.access_id": ACCESS_ID,
        "credential.hmac_key_create_observed": True,
    }
    assert "synthetic-secret" not in repr(result)
    assert "attacker" not in repr(result) and "used" not in repr(result)


@pytest.mark.parametrize("change", [
    "denied", "boolean_status", "ambiguous_status", "wrong_method", "wrong_service",
    "data_access", "wrong_resource_type", "other_project_label", "other_project_request",
    "other_project_metadata", "other_target_metadata", "other_target_project",
    "missing_response", "missing_metadata", "missing_access_id", "wrong_metadata_id",
    "inactive_key", "malformed_actor", "missing_event_id", "bad_resource_name",
    "incomplete_operation", "wrong_response_type", "malformed_resource",
])
def test_denied_incomplete_or_mismatched_event_fails_closed(change):
    row = deepcopy(event())
    payload = row["protoPayload"]
    metadata = payload["response"]["metadata"]
    if change == "denied":
        payload["status"] = {"code": 7, "message": "permission denied"}
    elif change == "boolean_status":
        payload["status"] = {"code": False}
    elif change == "ambiguous_status":
        payload["status"] = {"message": "unavailable"}
    elif change == "wrong_method":
        payload["methodName"] = "storage.hmacKeys.list"
    elif change == "wrong_service":
        payload["serviceName"] = "iam.googleapis.com"
    elif change == "data_access":
        row["logName"] = row["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_resource_type":
        row["resource"]["type"] = "project"
    elif change == "other_project_label":
        row["resource"]["labels"]["project_id"] = "other-project"
    elif change == "other_project_request":
        payload["request"]["projectId"] = "other-project"
    elif change == "other_project_metadata":
        metadata["projectId"] = "other-project"
    elif change == "other_target_metadata":
        metadata["serviceAccountEmail"] = f"other@{PROJECT}.iam.gserviceaccount.com"
    elif change == "other_target_project":
        payload["request"]["serviceAccountEmail"] = "backup@other-project.iam.gserviceaccount.com"
    elif change == "missing_response":
        payload.pop("response")
    elif change == "missing_metadata":
        payload["response"].pop("metadata")
    elif change == "missing_access_id":
        metadata.pop("accessId")
    elif change == "wrong_metadata_id":
        metadata["id"] = "other-project/GOOGEXAMPLE123456"
    elif change == "inactive_key":
        metadata["state"] = "INACTIVE"
    elif change == "malformed_actor":
        payload["authenticationInfo"]["principalEmail"] = "anonymous"
    elif change == "missing_event_id":
        row.pop("insertId")
    elif change == "bad_resource_name":
        payload["resourceName"] = "projects/other-project"
    elif change == "incomplete_operation":
        row["operation"] = {"first": True, "last": False}
    elif change == "wrong_response_type":
        payload["response"]["@type"] = "type.googleapis.com/google.storage.v1.HmacKeyMetadata"
    elif change == "malformed_resource":
        row["resource"] = "bad"
    assert normalize_gcp_hmac_key_created(row) is None


def test_explicit_zero_status_and_project_id_resource_are_supported():
    row = event()
    row["protoPayload"]["status"] = {"code": 0}
    row["protoPayload"]["resourceName"] = f"projects/{PROJECT}"
    assert normalize_gcp_hmac_key_created(row)["credential.access_id"] == ACCESS_ID
