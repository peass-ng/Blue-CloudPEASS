"""Live-shaped, synthetic Secret Manager Admin Activity evidence gates."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp_secret_versions_next import (
    normalize_gcp_secret_version_destroy,
    normalize_gcp_secret_version_disable,
    normalize_gcp_secret_delete,
)
from peaso.attack_detection.rules import Rule, detect_gcp_events


PROJECT = "gcp-labs-ly3gvnn7"
METHOD = "google.cloud.secretmanager.v1.SecretManagerService."
TYPE = "type.googleapis.com/google.cloud.secretmanager.v1."
SECRET = "synthetic-secret"
NUMERIC_PROJECT = "882210141464"


def event(operation: str = "Destroy", *, response: bool = False) -> dict:
    method = METHOD + operation + "SecretVersion"
    version = "1" if operation == "Destroy" else "2"
    observed = f"projects/{NUMERIC_PROJECT}/secrets/{SECRET}/versions/{version}"
    payload = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": "secretmanager.googleapis.com",
        "methodName": method,
        "status": {},
        "authenticationInfo": {"principalEmail": "operator@example.org"},
        "request": {
            "@type": TYPE + operation + "SecretVersionRequest",
            "name": f"projects/{PROJECT}/secrets/{SECRET}/versions/{version}",
        },
        "resourceName": observed,
    }
    if response:
        payload["response"] = {
            "@type": TYPE + "SecretVersion", "name": observed,
            "state": "DESTROYED" if operation == "Destroy" else "DISABLED",
        }
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "synthetic-event", "timestamp": "2026-10-18T19:10:13.772300721Z",
        "resource": {"type": "audited_resource", "labels": {
            "project_id": PROJECT, "method": method, "service": "secretmanager.googleapis.com"}},
        "protoPayload": payload,
    }


def test_live_shaped_destroy_without_response_reports_operation_only():
    detected = normalize_gcp_secret_version_destroy(event())
    assert detected is not None
    assert detected["secret.version_destroy_invoked"] is True
    assert detected["secret.version_state_confirmed"] is False
    assert "secret.version_state" not in detected
    assert detected["target.id"].endswith("/versions/1")
    assert normalize_gcp_secret_version_disable(event()) is None


def test_disable_requires_returned_state_and_is_not_destroy():
    detected = normalize_gcp_secret_version_disable(event("Disable", response=True))
    assert detected is not None
    assert detected["secret.version_state"] == "DISABLED"
    assert normalize_gcp_secret_version_destroy(event("Disable", response=True)) is None
    assert normalize_gcp_secret_version_disable(event("Disable")) is None


def test_destroy_with_consistent_response_confirms_state():
    detected = normalize_gcp_secret_version_destroy(event(response=True))
    assert detected is not None and detected["secret.version_state_confirmed"] is True
    assert detected["secret.version_state"] == "DESTROYED"


@pytest.mark.parametrize("operation,selection", [
    ("Destroy", {"secret.version_destroy_invoked": True}),
    ("Disable", {"secret.version_state": "DISABLED"}),
    ("Delete", {"secret.delete_invoked": True}),
])
def test_live_shaped_events_reach_detection_pipeline(operation, selection):
    row = event("Disable", response=True) if operation == "Disable" else event()
    if operation == "Delete":
        row = delete_event()
    method = METHOD + (operation + "SecretVersion" if operation != "Delete" else "DeleteSecret")
    rule = Rule(
        id=f"secret-{operation.lower()}", title=f"Observed {operation}", level="medium",
        description="Observed successful operation; review context.",
        technique_id=f"gcp-secret-{operation.lower()}", product="gcp",
        selection={"event.source": "secretmanager.googleapis.com", "event.name": method,
                   "event.outcome": "success", **selection},
    )
    found = detect_gcp_events([row], [rule])
    assert len(found) == 1
    assert found[0].target_id
    denied = deepcopy(row)
    denied["protoPayload"]["status"] = {"code": 7}
    assert detect_gcp_events([denied], [rule]) == []


@pytest.mark.parametrize("edit", [
    lambda e: e["protoPayload"].update(status={"code": 7}),
    lambda e: e["protoPayload"].update(status={"message": "denied"}),
    lambda e: e["protoPayload"].pop("status"),
    lambda e: e["protoPayload"]["request"].update(name="projects/other-project/secrets/synthetic-secret/versions/1"),
    lambda e: e["protoPayload"].update(resourceName="projects/882210141464/secrets/other/versions/1"),
    lambda e: e["protoPayload"].update(resourceName="projects/other-project/secrets/synthetic-secret/versions/1"),
    lambda e: e["resource"]["labels"].update(project_id="other-project"),
    lambda e: e["resource"]["labels"].update(method="unexpected"),
    lambda e: e["protoPayload"].update(methodName="unexpected"),
    lambda e: e["protoPayload"]["authenticationInfo"].pop("principalEmail"),
    lambda e: e.update(operation={"last": False}),
    lambda e: e.update(timestamp="not-a-time"),
    lambda e: e["protoPayload"].update(response={"@type": TYPE + "SecretVersion", "name": "other", "state": "DESTROYED"}),
])
def test_destroy_rejects_denied_incomplete_or_mismatched(edit):
    row = deepcopy(event())
    edit(row)
    assert normalize_gcp_secret_version_destroy(row) is None


@pytest.mark.parametrize("edit", [
    lambda e: e["protoPayload"].update(status={"code": 7}),
    lambda e: e["protoPayload"]["response"].update(state="ENABLED"),
    lambda e: e["protoPayload"]["response"].update(name="projects/882210141464/secrets/other/versions/2"),
    lambda e: e["protoPayload"]["request"].update(name="projects/other-project/secrets/synthetic-secret/versions/2"),
    lambda e: e["protoPayload"].update(resourceName="projects/882210141464/secrets/synthetic-secret/versions/1"),
])
def test_disable_rejects_denied_or_missing_target_proof(edit):
    row = deepcopy(event("Disable", response=True))
    edit(row)
    assert normalize_gcp_secret_version_disable(row) is None


def delete_event() -> dict:
    row = event()
    method = METHOD + "DeleteSecret"
    row["resource"]["labels"]["method"] = method
    row["protoPayload"]["methodName"] = method
    row["protoPayload"]["request"] = {
        "@type": TYPE + "DeleteSecretRequest",
        "name": f"projects/{PROJECT}/secrets/{SECRET}",
    }
    row["protoPayload"]["resourceName"] = f"projects/{NUMERIC_PROJECT}/secrets/{SECRET}"
    return row


def test_live_shaped_delete_is_operation_observation_only():
    detected = normalize_gcp_secret_delete(delete_event())
    assert detected is not None
    assert detected["secret.delete_invoked"] is True
    assert "secret.state" not in detected
    assert normalize_gcp_secret_version_destroy(delete_event()) is None


@pytest.mark.parametrize("edit", [
    lambda e: e["protoPayload"].update(status={"code": 7}),
    lambda e: e["protoPayload"]["request"].update(name="projects/other-project/secrets/synthetic-secret"),
    lambda e: e["protoPayload"].update(resourceName="projects/882210141464/secrets/other"),
    lambda e: e["protoPayload"].update(resourceName="projects/other-project/secrets/synthetic-secret"),
    lambda e: e["protoPayload"].update(response={"@type": TYPE + "Secret"}),
    lambda e: e["resource"]["labels"].update(method="unexpected"),
])
def test_delete_rejects_denied_mismatch_or_unsupported_response(edit):
    row = deepcopy(delete_event())
    edit(row)
    assert normalize_gcp_secret_delete(row) is None
