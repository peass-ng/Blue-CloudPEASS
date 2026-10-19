"""Live and archived report shapes group before pagination, with member-level filters."""
from copy import deepcopy
import json

import pytest
from fastapi.testclient import TestClient

from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import SQLiteStore, FileArtifacts
from peaso.storage.reports import publish_report
from peaso.finding_groups import group_id
from tests.test_peaso_api import TestIdentities


def fixture_report():
    rows = []
    for number in range(125):
        region = ("us-east-1", "eu-north-1")[number % 2]
        rows.append(dict(id=f"member-{number:04d}", provider="aws", category="hardening", check_id="fixture.retention",
            title="Log retention", severity="medium", status="FAIL" if number < 120 else "PASS", scope="123456789012/" + region,
            region=region, resource_id=f"stable-{number}", native_resource_id=f"arn:aws:logs:{region}:123456789012:log-group:log-{number}", resource_name=f"log-{number}",
            frameworks=["Reviewed"], evidence={"retention_days": 7 if number < 120 else 365},
            evidence_summary=f"log-{number} retains logs for {7 if number < 120 else 365} days.", remediation="Set retention to 365 days."))
    rows.append(dict(rows[0], id="guard-1", check_id="fixture.guardduty", title="GuardDuty", resource_id="scope:123456789012/us-east-1"))
    return dict(schema_version="1.0", snapshot_id="fixture", provider="aws", scopes=["123456789012/us-east-1", "123456789012/eu-north-1"], created_at="2026-10-19T00:00:00Z",
        findings=rows, coverage=[], resources=[], graphs={}, stats={"finding_count": 126, "by_status": {"FAIL": 121, "PASS": 5}, "by_severity": {"medium": 121}})


@pytest.fixture(params=[False, True], ids=["inline-old-report", "chunked-bundle"])
def live(request, tmp_path):
    store, artifacts = SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    connector = store.add_connector("alice", {"provider": "aws", "name": "fixture"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    report = fixture_report()
    reference = publish_report(artifacts, "alice", job["id"], report) if request.param else artifacts.put("alice", job["id"], "report", report)
    with store.transaction() as db:
        db.execute("UPDATE jobs SET status='completed',report=? WHERE id=?", (reference, job["id"]))
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"), store=store, artifacts=artifacts, authenticator=TestIdentities())
    with TestClient(app, base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer alice"}) as client:
        yield client, job["id"], report


def test_one_card_per_check_before_pagination_and_legacy_observations_are_retained(live):
    client, scan, report = live
    path = f"/api/scans/{scan}/findings"
    response = client.get(path, params={"aggregation": "check", "limit": 1})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 2 and len(data["items"]) == 1 and data["next_offset"] == 1
    second = client.get(path, params={"aggregation": "check", "limit": 1, "offset": 1}).json()
    assert second["total"] == 2 and second["next_offset"] is None
    assert data["items"][0]["check_id"] != second["items"][0]["check_id"]
    assert client.get(path).json()["total"] == 126


def test_member_pages_retain_exact_evidence_status_native_asset_and_location(live):
    client, scan, _ = live
    base = f"/api/scans/{scan}/finding-groups/" + group_id("aws", "fixture.retention")
    seen = []
    for offset, expected in [(0, 50), (50, 50), (100, 25)]:
        response = client.get(base, params={"members_offset": offset})
        assert response.status_code == 200, response.text
        group = response.json()
        assert group["status_counts"] == {"FAIL": 120, "PASS": 5}
        assert group["affected_regions"] == ["eu-north-1", "us-east-1"]
        assert group["members_total"] == 125 and len(group["members"]) == expected
        seen += group["members"]
    assert len({member["id"] for member in seen}) == 125
    for member in seen:
        number = int(member["id"].rsplit("-", 1)[-1])
        assert member["asset"] == f"log-{number}"
        assert member["evidence_summary"] == f"log-{number} retains logs for {7 if number < 120 else 365} days."
        original = client.get("/api" + member["detail_path"])
        assert original.status_code == 200
        assert original.json()["evidence"]["retention_days"] == (7 if number < 120 else 365)


def test_filter_members_before_grouping_and_keep_filters_on_the_group(live):
    client, scan, _ = live
    data = client.get(f"/api/scans/{scan}/findings", params={"aggregation": "check", "status": "PASS"}).json()
    assert data["total"] == 1 and data["items"][0]["status"] == "PASS"
    assert data["items"][0]["member_filters"] == {"status": "PASS"}
    item = data["items"][0]
    group = client.get(f"/api/scans/{scan}/finding-groups/{item['id']}", params=item["member_filters"]).json()
    assert group["members_total"] == 5 and all(member["status"] == "PASS" for member in group["members"])
    data = client.get(f"/api/scans/{scan}/findings", params={"aggregation": "check", "search": "log-119"}).json()
    assert data["total"] == 1 and data["items"][0]["member_count"] == 1


def test_grouped_summary_counts_checks_without_changing_coverage(live):
    client, scan, _ = live
    original = client.get(f"/api/scans/{scan}/summary").json()
    grouped = client.get(f"/api/scans/{scan}/summary?aggregation=check").json()
    assert original["finding_count"] == 126
    assert grouped["finding_count"] == grouped["stats"]["finding_count"] == 2
    assert grouped["stats"]["observation_count"] == 126
    assert grouped["stats"]["by_status"] == {"FAIL": 2}
    assert grouped["stats"]["by_category"] == {"hardening": 2}
    assert grouped["coverage_count"] == original["coverage_count"]


def test_group_ownership_bounds_and_unknown_ids(live):
    client, scan, _ = live
    path = f"/api/scans/{scan}/finding-groups/" + group_id("aws", "fixture.retention")
    assert client.get(path, params={"members_limit": 101}).status_code == 422
    assert client.get(path, params={"members_offset": -1}).status_code == 422
    assert client.get(path + "invalid").status_code == 404
    client.headers["Authorization"] = "Bearer bob"
    assert client.get(path).status_code == 404
    assert client.get(f"/api/scans/{scan}/findings?aggregation=check").status_code == 404


def test_grouped_downloads_include_all_assets_for_old_and_new_reports(live):
    client, scan, report = live
    response = client.get(f"/api/scans/{scan}/report?aggregation=check")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["finding_grouping"] == "check-v1" and len(value["findings"]) == 2
    assert sum(len(group["observations"]) for group in value["findings"]) == len(report["findings"])
    markdown = client.get(f"/api/scans/{scan}/report?format=markdown&aggregation=check")
    assert markdown.status_code == 200
    assert markdown.text.count("### FAIL:") == 2
    assert "log-124" in markdown.text and "log-0" in markdown.text
