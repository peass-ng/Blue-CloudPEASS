"""Mocked native API Keys/Service Usage project alias contract; no cloud calls."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, plan_collection
from peaso.snapshot import validate


SCOPE = "projects/sample-project"
NUMBER = "projects/123456789"
SERVICE = "example.googleapis.com"
CHECK = "gcp.apikeys.active_service_restrictions"


class Transport:
    def __init__(self, *, project="valid", key_parent=NUMBER, service_parent=NUMBER,
                 state="DISABLED", missing_project_receipt=False, denied_service=False):
        self.project, self.key_parent, self.service_parent = project, key_parent, service_parent
        self.state = state
        self.missing_project_receipt = missing_project_receipt
        self.denied_service = denied_service
        self.evidence, self.requests = [], []
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        ref = f"request-{self.calls}"
        assert method == "GET" and kwargs["scope"] == SCOPE
        self.requests.append(url)
        if url == "https://cloudresourcemanager.googleapis.com/v3/" + SCOPE:
            if self.project == "denied":
                error = gcp.ReadError("denied", "permission_denied")
                error.request_id = ref
                self.evidence.append({"id": ref, "url": url, "method": method, "scope": SCOPE, "status": "denied"})
                raise error
            response = {"name": NUMBER, "projectId": "sample-project", "projectNumber": "123456789"}
            if self.project == "foreign":
                response["projectId"] = "different-project"
            elif self.project == "mismatch":
                response["projectNumber"] = "987654321"
            elif self.project == "missing":
                response = {}
        elif url == "https://compute.googleapis.com/compute/v1/" + SCOPE:
            response = {}
        elif url == "https://apikeys.googleapis.com/v2/" + SCOPE + "/locations/global/keys":
            response = {"keys": [{"name": self.key_parent + "/locations/global/keys/fixture-key",
                                  "restrictions": {"apiTargets": [{"service": SERVICE}]}}]}
        elif url == "https://serviceusage.googleapis.com/v1/" + SCOPE + "/services":
            if self.denied_service:
                error = gcp.ReadError("denied", "permission_denied")
                error.request_id = ref
                self.evidence.append({"id": ref, "url": url, "method": method, "scope": SCOPE, "status": "denied"})
                raise error
            response = {"services": [{"name": self.service_parent + "/services/" + SERVICE,
                                      "state": self.state}]}
        else:
            raise AssertionError("unexpected request: " + url)
        if not (self.missing_project_receipt and url.endswith("/v3/" + SCOPE)):
            self.evidence.append({"id": ref, "url": url, "method": method, "scope": SCOPE, "status": "collected"})
        return deepcopy(response), ref


class TamperedProjectCollector(gcp.GCPCollector):
    tamper = None

    def run_jobs(self, jobs):
        super().run_jobs(jobs)
        envelope = self.collections.get(("project", SCOPE))
        if envelope and self.tamper == "duplicate" and len(envelope["items"]) == 1:
            envelope["items"].append(deepcopy(envelope["items"][0]))
        if envelope and self.tamper == "stale" and envelope["items"]:
            envelope["items"][0]["_provenance"]["collected_at"] = "2020-01-01T00:00:00+00:00"
        if envelope and self.tamper == "partial":
            envelope["status"] = envelope["coverage_status"] = "partial"
            envelope["error"] = {"kind": "unavailable", "code": "incomplete_project_identity"}
        if envelope and self.tamper == "identity_field_denied" and envelope["items"]:
            envelope["items"][0].setdefault("_coverage", {})["projectId"] = {"status": "denied"}


def run(*, tamper=None, **kwargs):
    request = {"connector": {"provider": "gcp", "scopes": [SCOPE], "options": {
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}}, "checks": [CHECK]}
    requirements = plan_collection(request)
    assert requirements == ["api_key", "service_usage"]
    transport = Transport(**kwargs)
    collector = TamperedProjectCollector(request["connector"], requirements, transport=transport)
    collector.tamper = tamper
    assert "project" in collector.needed
    snapshot = collector.collect()
    validate(snapshot)
    statuses = [row["status"] for row in evaluate_snapshot(snapshot, checks=[CHECK])["findings"]]
    key = next(row for row in snapshot["collections"] if row["type"] == "api_key")
    usage = next(row for row in snapshot["collections"] if row["type"] == "service_usage")
    return statuses, key, usage, snapshot, transport


def test_numeric_native_names_are_bound_by_independent_project_read():
    statuses, key, usage, snapshot, transport = run()
    assert statuses == ["FAIL"]
    assert len(transport.requests) == 3
    assert all(url.startswith(("https://cloudresourcemanager.googleapis.com/v3/" + SCOPE,
                               "https://apikeys.googleapis.com/v2/" + SCOPE,
                               "https://serviceusage.googleapis.com/v1/" + SCOPE)) for url in transport.requests)
    for envelope in (key, usage):
        row = envelope["items"][0]
        assert row["name"].startswith(SCOPE + "/")
        assert row["rawNativeName"].startswith(NUMBER + "/")
        assert row["native_id"] == row["_resource_id"] == row["rawNativeName"]
        proof = row["_provenance"]["derived_project_alias"]
        assert proof["native_name"] == row["rawNativeName"]
        assert proof["canonical_name"] == row["name"]
        assert proof["project_identity_source_requests"]
    assert any(c["type"] == "project" and c["scope"] == SCOPE for c in snapshot["collections"])


@pytest.mark.parametrize("state,expected", [("ENABLED", "UNKNOWN"), ("DISABLED", "FAIL")])
def test_canonical_project_id_names_still_evaluate(state, expected):
    statuses, key, usage, _, _ = run(key_parent=SCOPE, service_parent=SCOPE, state=state)
    assert statuses == [expected]
    assert "rawNativeName" not in key["items"][0]
    assert "rawNativeName" not in usage["items"][0]


@pytest.mark.parametrize("change", [
    {"project": "missing"}, {"project": "denied"}, {"project": "foreign"},
    {"project": "mismatch"}, {"missing_project_receipt": True},
    {"tamper": "duplicate"}, {"tamper": "stale"}, {"tamper": "partial"},
    {"tamper": "identity_field_denied"},
    {"key_parent": "projects/999999999"}, {"service_parent": "projects/999999999"},
    {"denied_service": True},
])
def test_unbound_or_foreign_native_identity_stays_unknown(change):
    statuses, key, usage, _, _ = run(**change)
    assert statuses == ["UNKNOWN"]
    if change.get("project") or change.get("tamper") or change.get("missing_project_receipt"):
        assert "rawNativeName" not in key["items"][0]
        assert "rawNativeName" not in usage["items"][0]
