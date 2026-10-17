"""Captured Secret Manager schedule and distinct GKE zone declaration boundaries."""
from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.checks import CHECKS


REGISTRY = {check.id: check for check in CHECKS}
SECRET = REGISTRY["gcp.claude.secret.rotation_90_days"]
GKE = REGISTRY["gcp.claude.gke.zone_redundant"]
CAPTURE = "2026-10-10T12:00:00Z"


def secret(period="2592000s", next_time="2026-10-11T12:00:00Z"):
    return {"rotation": {"rotationPeriod": period, "nextRotationTime": next_time},
            "_provenance": {"collected_at": CAPTURE}}


@pytest.mark.parametrize("period,next_time,expected", [
    ("2592000s", "2026-10-11T12:00:00Z", "PASS"),
    ("7776000s", "2026-10-10T12:00:01Z", "PASS"),
    ("7776000s", "2026-10-10T12:00:00Z", "FAIL"),
    ("2592000s", "2026-10-09T12:00:00Z", "FAIL"),
    ("7776000.000000001s", "2026-10-11T12:00:00Z", "FAIL"),
    ("7776001s", "2026-10-11T12:00:00Z", "FAIL"),
])
def test_declared_secret_rotation_uses_exact_period_and_capture(period, next_time, expected):
    item = secret(period, next_time)
    before = deepcopy(item)
    assert SECRET.evaluate(item, {})[0] == expected
    assert item == before


def test_secret_rotation_uses_snapshot_clock_when_item_provenance_absent():
    item = secret()
    del item["_provenance"]
    assert SECRET.evaluate(item, {"context": {"created_at": CAPTURE}})[0] == "PASS"
    assert SECRET.evaluate(item, {"context": {"created_at": "2026-10-12T12:00:00Z"}})[0] == "FAIL"


@pytest.mark.parametrize("item,index", [
    (secret(next_time="bad"), {}),
    (secret(next_time="2026-10-11T12:00:00"), {}),
    ({"rotation": {"rotationPeriod": "2592000s"}, "_provenance": {"collected_at": CAPTURE}}, {}),
    ({"rotation": {"nextRotationTime": "2026-10-11T12:00:00Z"}, "_provenance": {"collected_at": CAPTURE}}, {}),
    (secret(period="3599s"), {}),
    (secret(period="2592000.1234567890s"), {}),
    (secret(period=2592000), {}),
    ({**secret(), "rotation": {**secret()["rotation"], "_coverage": {"nextRotationTime": {"status": "denied"}}}}, {}),
    ({**secret(), "collection_status": "denied"}, {}),
    ({"rotation": {"rotationPeriod": "2592000s", "nextRotationTime": "2026-10-11T12:00:00Z"}}, {}),
])
def test_missing_malformed_or_denied_schedule_evidence_is_unknown(item, index):
    assert SECRET.evaluate(item, index)[0] == "UNKNOWN"


def test_observed_unconfigured_rotation_fails_without_claiming_subscriber_behavior():
    status, evidence = SECRET.evaluate({"name": "projects/p/secrets/s"}, {})
    assert status == "FAIL" and evidence["rotation"] is None
    status, evidence = SECRET.evaluate(secret(), {})
    assert status == "PASS" and "subscriber action is unverified" in evidence["semantics"]


def cluster(location="us-central1-a", locations=None):
    return {"location": location, "locations": locations if locations is not None else [
        "us-central1-a", "us-central1-b", "us-central1-c"]}


@pytest.mark.parametrize("locations,expected", [
    (["us-central1-a", "us-central1-b", "us-central1-c"], "PASS"),
    (["us-central1-a", "us-central1-a", "us-central1-b"], "FAIL"),
    (["us-central1-a", "us-central1-b"], "FAIL"),
    (["us-central1-a"], "FAIL"),
    ([], "FAIL"),
])
def test_zonal_cluster_counts_distinct_declared_node_zones(locations, expected):
    item = cluster(locations=locations)
    before = deepcopy(item)
    status, evidence = GKE.evaluate(item, {})
    assert status == expected
    assert evidence["distinct_zone_count"] == len(set(locations))
    assert item == before


def test_regional_cluster_is_not_applicable_without_node_location_claim():
    assert GKE.evaluate({"location": "us-central1"}, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("item", [
    {"location": "not-a-zone", "locations": []},
    {"location": "us-central1-a"},
    {"location": "us-central1-a", "locations": "us-central1-a"},
    cluster(locations=["us-central1-a", "us-central1-b", "europe-west1-c"]),
    cluster(locations=["us-central1-b", "us-central1-c", "us-central1-f"]),
    cluster(locations=["us-central1-a", "us-central1-b", "bad-zone"]),
    {**cluster(), "collection_status": "denied"},
])
def test_malformed_foreign_missing_or_denied_gke_zone_evidence_is_unknown(item):
    assert GKE.evaluate(item, {})[0] == "UNKNOWN"
