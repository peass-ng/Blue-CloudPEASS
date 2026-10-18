"""The attack source verifies real Logging reads and platform project ownership."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from peaso.server.gcp_attack_logs import (
    GcpLogAccessError, analyze_gcp_source, check_gcp_source,
)


PROJECT = "customer-demo-123"
SETTINGS = SimpleNamespace(gcp_platform_sa_secret_arn="secret")


class Response:
    def __init__(self, value, status=200):
        self.status_code = status
        self.content = json.dumps(value).encode()
        self.closed = False

    def iter_content(self, chunk_size):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]

    def close(self):
        self.closed = True


class Credentials:
    created = []

    def __init__(self, auth, **kwargs):
        self.created.append(self)
        self.auth = auth
        self.closed = False

    def headers(self):
        return {"Authorization": "Bearer do-not-report"}

    def close(self):
        self.closed = True


def setup(monkeypatch, responses):
    calls = []
    Credentials.created = []
    monkeypatch.setattr("peaso.server.gcp_attack_logs.Credentials", Credentials)

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return responses[len(calls) - 1]

    monkeypatch.setattr("peaso.server.gcp_attack_logs.requests.request", request)
    return calls


def source(kind="gcp_audit", *, project=PROJECT, cluster=None):
    return SimpleNamespace(kind=kind, project_id=project, cluster_id=cluster)


def test_exact_project_scope_and_actual_entries_probe(monkeypatch):
    calls = setup(monkeypatch, [Response({"entries": []})])
    result = check_gcp_source({"method": "token", "token": "x"}, [f"projects/{PROJECT}"], {}, SETTINGS, source())
    assert result["source_status"] == "accessible"
    assert "no matching audit entry" in result["coverage"]
    assert calls[0][0:2] == ("POST", "https://logging.googleapis.com/v2/entries:list")
    body = calls[0][2]["json"]
    assert body["resourceNames"] == [f"projects/{PROJECT}"]
    assert "cloudaudit.googleapis.com/activity" in body["filter"]
    assert body["pageSize"] == 100
    assert Credentials.created[0].closed


def test_rejects_platform_project_and_out_of_scope_before_credentials(monkeypatch):
    calls = setup(monkeypatch, [])
    with pytest.raises(GcpLogAccessError, match="platform_project_forbidden"):
        check_gcp_source({}, ["*"], {"all_projects": True}, SETTINGS,
                         source(project="billing-static-info-no-delete"))
    with pytest.raises(GcpLogAccessError, match="project_outside_connector_scope"):
        check_gcp_source({}, ["projects/other-project-123"], {}, SETTINGS, source())
    with pytest.raises(GcpLogAccessError, match="project_outside_connector_scope"):
        check_gcp_source({}, ["organizations/1234"], {"discover_projects": True}, SETTINGS, source())
    assert calls == [] and Credentials.created == []


def test_hosted_identity_requires_live_customer_approval(monkeypatch):
    import peaso.server.gcp_attack_logs as module
    monkeypatch.setattr(module, "load_service_account", lambda arn: {"type": "service_account"})
    label = "hacktricks-cspm-" + "a" * 20
    auth = {"method": "platform-service-account", "project_proof_label": label}
    calls = setup(monkeypatch, [Response({"projectId": PROJECT, "name": "projects/1234", "state": "ACTIVE",
                                         "labels": {label: "approved"}}), Response({"entries": []})])
    result = check_gcp_source(auth, [f"projects/{PROJECT}"], {}, SETTINGS, source())
    assert result["source_status"] == "accessible"
    assert calls[0][1].endswith(f"/projects/{PROJECT}")
    assert Credentials.created[0].auth["method"] == "service-account"

    setup(monkeypatch, [Response({"projectId": PROJECT, "name": "projects/1234", "state": "ACTIVE",
                                      "labels": {}})])
    with pytest.raises(GcpLogAccessError, match="customer_project_not_approved"):
        check_gcp_source(auth, [f"projects/{PROJECT}"], {}, SETTINGS, source())


def test_denied_response_is_stable_and_does_not_leak_provider_body(monkeypatch):
    setup(monkeypatch, [Response({"error": {"message": "secret credential data"}}, 403)])
    with pytest.raises(GcpLogAccessError) as exc:
        check_gcp_source({"method": "token", "token": "x"}, [PROJECT], {}, SETTINGS, source())
    assert exc.value.code == "log_read_denied"
    assert "secret" not in str(exc.value)
    assert Credentials.created[0].closed


def test_response_limit_stops_stream_and_closes_it(monkeypatch):
    response = Response({"entries": []})
    response.content = b"x" * 5_000_001
    setup(monkeypatch, [response])
    with pytest.raises(GcpLogAccessError, match="log_response_too_large"):
        check_gcp_source({"method": "token", "token": "x"}, [PROJECT], {}, SETTINGS, source())
    assert response.closed
    assert Credentials.created[0].closed


def test_gke_cluster_filter_and_bounded_pagination(monkeypatch):
    entry = {"insertId": "1", "resource": {"type": "k8s_cluster"},
             "protoPayload": {"serviceName": "k8s.io", "methodName": "clusterrolebindings.create"}}
    calls = setup(monkeypatch, [Response({"entries": [entry], "nextPageToken": "next"}),
                                Response({"entries": [entry]})])
    monkeypatch.setattr("peaso.attack_detection.detect_kubernetes_events", lambda records: [])
    result = analyze_gcp_source({"method": "token", "token": "x"}, [PROJECT], {}, SETTINGS,
                                source("gke_audit", cluster="customer-cluster"))
    assert result["coverage"]["events_read"] == 2
    assert result["coverage"]["truncated"] is False
    assert calls[1][2]["json"]["pageToken"] == "next"
    assert 'resource.labels.cluster_name="customer-cluster"' in calls[0][2]["json"]["filter"]
    assert Credentials.created[0].closed


def test_gke_requires_exact_cluster_name(monkeypatch):
    setup(monkeypatch, [])
    with pytest.raises(GcpLogAccessError, match="select_valid_gke_cluster"):
        check_gcp_source({}, [PROJECT], {}, SETTINGS, source("gke_audit", cluster='x" OR true'))
