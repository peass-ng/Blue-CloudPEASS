"""Exact Entra credential-add activity; no inferred compromise or privileges."""

from __future__ import annotations

import copy
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from peaso.attack_detection import Rule, detect_azure_events
from peaso.attack_detection.entra import normalize_entra_credential_add
from peaso.server import entra_attack_logs


TENANT = "12345678-1234-1234-1234-123456789abc"
ACTOR = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
TARGET = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
RULE = Rule(
    id="synthetic-entra", title="Synthetic credential activity", level="medium",
    description="Test only", technique_id="azure-entra-service-principal-credential-addition",
    product="azure", selection={
        "cloud.provider": "azure", "event.source": "entra.directoryAudit",
        "event.name": "Add service principal credentials", "event.outcome": "success",
        "credential.add_observed": True,
    },
)


def row():
    return {
        "id": "directory-audit-1",
        "activityDateTime": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "category": "ApplicationManagement",
        "loggedByService": "Core Directory",
        "activityDisplayName": "Add service principal credentials",
        "result": "success",
        "operationType": "Add",
        "initiatedBy": {"user": {"id": ACTOR}},
        "targetResources": [{"id": TARGET, "type": "ServicePrincipal", "displayName": "sensitive app"}],
    }


def normalized(event):
    return normalize_entra_credential_add(
        event, tenant=TENANT, event_id=hashlib.sha256(event["id"].encode()).hexdigest(),
        event_time=event["activityDateTime"],
    )


def test_completed_service_principal_credential_add_matches_reviewed_rule():
    event = normalized(row())
    assert event is not None
    assert event["actor.id"] == ACTOR and event["target.id"] == TARGET
    matches = detect_azure_events([event], [RULE])
    assert len(matches) == 1
    assert matches[0].evidence["credential.add_observed"] is True
    assert "sensitive app" not in str(matches[0])


@pytest.mark.parametrize("change", [
    {"result": "failure"},
    {"category": "UserManagement"},
    {"loggedByService": "Other Service"},
    {"activityDisplayName": "Remove service principal credentials"},
    {"operationType": "Delete"},
    {"targetResources": [{"id": TARGET, "type": "Application"}]},
    {"targetResources": [{"id": TARGET, "type": "ServicePrincipal"}, {"id": ACTOR, "type": "ServicePrincipal"}]},
    {"targetResources": [{"id": "not-a-uuid", "type": "ServicePrincipal"}]},
    {"initiatedBy": {"user": {"id": "invalid"}}},
    {"initiatedBy": {"user": {"id": ACTOR}, "app": {"servicePrincipalId": TARGET}}},
])
def test_ambiguous_or_unrelated_event_fails_closed(change):
    event = row()
    event.update(copy.deepcopy(change))
    assert normalized(event) is None


def test_reader_does_not_publish_noisy_credential_activity_as_attack(monkeypatch):
    from types import SimpleNamespace

    claims = base64.urlsafe_b64encode(json.dumps({
        "tid": TENANT, "aud": "https://graph.microsoft.com",
    }).encode()).decode().rstrip("=")

    class API:
        def token(self, audience): return f"header.{claims}.signature"
        def request(self, url, **kwargs): return {"value": [row()]}
        def close(self): pass

    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: API())
    result = entra_attack_logs.analyze_entra_source(
        {"tenant_id": TENANT}, [], {}, SimpleNamespace(kind="entra_directory_audit", tenant_id=TENANT))
    assert result["coverage"]["events_read"] == 1
    assert result["coverage"]["credential_add_candidates"] == 1
    assert result["coverage"]["detection_status"] == "not_implemented"
    assert result["detections"] == []
    assert "sensitive app" not in str(result)
