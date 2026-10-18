"""Public GCP opt-in audit routing with stubbed read-only Logging evidence."""
from datetime import datetime, timedelta, timezone

from peaso.collectors import collect_live
from peaso.collectors import gcp
from tests.archived_check_contract import evaluate_snapshot


def test_explicit_audit_inventory_without_requirement_list_routes_native_producer(monkeypatch):
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=2)).isoformat()
    end = (now - timedelta(hours=1)).isoformat()
    calls = []

    class Transport:
        evidence = []

        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            assert method == "POST" and url == "https://logging.googleapis.com/v2/entries:list"
            return {"entries": [{
                "insertId": "observed-1", "timestamp": start,
                "logName": "projects/demo-project/logs/cloudaudit.googleapis.com%2Factivity",
                "resource": {"type": "service_account", "labels": {"project_id": "demo-project"}},
                "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                    "serviceName": "iam.googleapis.com",
                    "methodName": "google.iam.admin.v1.CreateServiceAccount",
                    "authenticationInfo": {"principalEmail": "unapproved@example.com"},
                    "status": {"code": 0}},
            }]}, "stub-request-1"

        def close(self):
            pass

    monkeypatch.setattr(gcp, "Credentials", lambda *args, **kwargs: None)
    monkeypatch.setattr(gcp, "Transport", lambda *args, **kwargs: Transport())
    connector = {"provider": "gcp", "scopes": ["projects/demo-project"], "auth": {},
        "options": {"inventories": ["audit_log"],
            "audit_window": {"start": start, "end": end, "classes": ["activity"]},
            "audit_detection_policy": {"approved_identity_admins": []},
            "max_pages": 2, "max_calls": 10, "max_resources": 100}}
    snapshot = collect_live(connector)
    audit = [row for row in snapshot["collections"] if row["type"] == "audit_log"]
    assert len(calls) == 1
    assert len(audit) == 1 and audit[0]["status"] == "collected"
    report = evaluate_snapshot(snapshot, checks=["gcp_logging_detect_t1136"])
    assert any(row["status"] == "FAIL" for row in report["findings"])
