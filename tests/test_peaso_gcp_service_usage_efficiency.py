"""Read-only Service Usage pagination through the normal collector and registered engine."""
from __future__ import annotations

import copy

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate

CHECK = "gcp.ports.project_service_cloudasset_api_enabled"
SCOPE = "projects/p-one"
SERVICE = SCOPE + "/services/cloudasset.googleapis.com"


class Transport:
    def __init__(self, state="ENABLED", fault=None, next_page=False):
        self.state, self.fault, self.next_page = state, fault, next_page
        self.requests = []
        self.evidence = []
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        rid = f"request-{self.calls}"
        params = copy.deepcopy(kwargs.get("params") or {})
        self.requests.append((method, url, params))
        if url == "https://cloudresourcemanager.googleapis.com/v3/" + SCOPE:
            data = {"name": SCOPE, "projectId": "p-one", "projectNumber": "123"}
        elif url == "https://compute.googleapis.com/compute/v1/" + SCOPE:
            data = {}
        elif url == "https://serviceusage.googleapis.com/v1/" + SCOPE + "/services":
            assert method == "GET" and "filter" not in params
            if self.fault == "denied" or self.fault == "throttled" and params.get("pageToken") == "next":
                exc = gcp.ReadError("denied" if self.fault == "denied" else "unavailable", "api_error",
                    http_status=403 if self.fault == "denied" else 429)
                exc.request_id = rid
                self.evidence.append({"id": rid, "method": method, "url": url, "status": exc.status, "error": exc.error})
                raise exc
            if self.next_page and "pageToken" not in params:
                data = {"services": [{"name": SERVICE, "state": self.state}], "nextPageToken": "next"}
            elif self.fault == "bad_token":
                data = {"services": [{"name": SERVICE, "state": self.state}], "nextPageToken": 42}
            else:
                data = {"services": [{"name": SCOPE + "/services/other.googleapis.com", "state": "ENABLED"}]
                        if self.next_page else [] if self.state is None else [{"name": SERVICE, "state": self.state}]}
        else:
            raise AssertionError("unexpected read: " + url)
        self.evidence.append({"id": rid, "method": method, "url": url, "status": "collected"})
        return copy.deepcopy(data), rid


def run(state="ENABLED", fault=None, next_page=False, **options):
    transport = Transport(state, fault, next_page)
    connector = {"provider": "gcp", "scopes": [SCOPE], "auth": {"method": "fixture"},
                 "options": {"inventories": ["project", "service_usage"], "include_inherited": False,
                             "metrics_scopes": False, "concurrency": 1, **options}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    validate(snapshot)
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CHECK])["findings"] if f["check_id"] == CHECK]
    assert len(findings) == 1
    service_requests = [r for r in transport.requests if "serviceusage.googleapis.com" in r[1]]
    return findings[0]["status"], service_requests, snapshot


@pytest.mark.parametrize(("state", "expected"), [("ENABLED", "PASS"), ("DISABLED", "FAIL"), (None, "UNKNOWN")])
def test_complete_native_states_preserved(state, expected):
    status, requests, snapshot = run(state)
    assert status == expected
    assert len(requests) == 1 and requests[0][2] == {"pageSize": 200}
    assert snapshot["metadata"]["service_usage_mode"] == "complete_list"


@pytest.mark.parametrize(("configured", "expected"), [(25, 25), (500, 200)])
def test_explicit_page_size_remains_a_bound(configured, expected):
    status, requests, _ = run(page_size=configured)
    assert status == "PASS" and requests[0][2] == {"pageSize": expected}


def test_next_page_token_and_complete_result():
    status, requests, _ = run(next_page=True)
    assert status == "PASS" and len(requests) == 2
    assert requests[0][2] == {"pageSize": 200}
    assert requests[1][2] == {"pageSize": 200, "pageToken": "next"}


@pytest.mark.parametrize(("fault", "next_page"), [("throttled", True), ("denied", False), ("bad_token", False)])
def test_unavailable_or_malformed_inventory_stays_unknown(fault, next_page):
    status, requests, snapshot = run(fault=fault, next_page=next_page)
    assert status == "UNKNOWN"
    collection = next(row for row in snapshot["collections"] if row["type"] == "service_usage")
    assert collection["status"] in ("partial", "denied", "unknown")


def test_resource_budget_keeps_a_truncated_inventory_unknown():
    status, requests, snapshot = run(next_page=True, max_resources=2)
    assert status == "UNKNOWN" and len(requests) == 2
    collection = next(row for row in snapshot["collections"] if row["type"] == "service_usage")
    assert collection["status"] == "partial"
    assert collection["error"]["code"] == "resource_limit"
