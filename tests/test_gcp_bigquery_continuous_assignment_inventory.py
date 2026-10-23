"""Effective continuous reservation assignments are read without query data."""

import sys
import types
from pathlib import Path

import pytest


PROJECT = "projects/p1"
RESERVATION = "projects/admin/locations/US/reservations/continuous"
ASSIGNMENT = RESERVATION + "/assignments/a1"


def collect(monkeypatch, *, denied=False, wrong_reservation=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/datasets"):
                return {"datasets": [{"id": "p1:source", "datasetReference":
                    {"projectId": "p1", "datasetId": "source"}}]}, "datasets"
            if url.endswith("/datasets/source"):
                return {"id": "p1:source", "datasetReference":
                    {"projectId": "p1", "datasetId": "source"}, "location": "US", "access": []}, "dataset"
            if url.endswith(":searchAllAssignments"):
                assert kwargs["params"]["query"] == "assignee=projects/p1"
                return {"assignments": [{"name": ASSIGNMENT, "assignee": PROJECT,
                    "jobType": "CONTINUOUS", "state": "ACTIVE"},
                    {"name": RESERVATION + "/assignments/query", "jobType": "QUERY"}]}, "assignments"
            if url.endswith("/reservations/continuous"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"name": RESERVATION + ("-wrong" if wrong_reservation else ""),
                        "edition": "ENTERPRISE", "slotCapacity": "100"}, "reservation"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_continuous_assignment"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    return next(row for row in collector.collect()["collections"]
                if row["type"] == "bigquery_continuous_assignment")


def test_assignment_and_admin_project_reservation_are_joined(monkeypatch):
    row = collect(monkeypatch)
    assert row["status"] == "collected"
    assignment, = row["items"]
    assert assignment["name"] == ASSIGNMENT
    assert assignment["sourceLocation"] == "US"
    assert assignment["reservationEdition"] == "ENTERPRISE"
    assert assignment["_coverage"]["reservationDetails"]["status"] == "collected"


@pytest.mark.parametrize("denied,wrong_reservation", [(True, False), (False, True)])
def test_denied_or_mismatched_reservation_never_supplies_edition(
        monkeypatch, denied, wrong_reservation):
    row = collect(monkeypatch, denied=denied, wrong_reservation=wrong_reservation)
    assignment, = row["items"]
    assert "reservationEdition" not in assignment
    assert assignment["_coverage"]["reservationDetails"]["status"] in {"denied", "malformed"}
