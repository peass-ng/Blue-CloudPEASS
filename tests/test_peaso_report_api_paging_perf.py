"""Report paging parity and artifact-read bounds for compact manifests."""
import copy
from collections import Counter

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server.app import create_app
from peaso.server.config import Settings
from peaso.storage import StoreError


SCAN = "1" * 32


class Users:
    def authenticate(self, header):
        if header == "Bearer alice":
            return Identity("alice")
        if header == "Bearer bob":
            return Identity("bob")
        raise HTTPException(401, "Invalid authentication")


class Store:
    def job(self, tenant, ident):
        if tenant != "alice" or ident != SCAN:
            raise StoreError(404, "Scan not found")
        return {"id": SCAN, "status": "completed", "report": "manifest"}


class Artifacts:
    def __init__(self, items):
        self.items = items
        self.reads = Counter()

    def get(self, tenant, reference):
        assert tenant == "alice"
        self.reads[reference] += 1
        return copy.deepcopy(self.items[reference])


@pytest.fixture
def api(tmp_path):
    rows = []
    for index in range(36):
        rows.append({"id": f"finding-{index:03d}", "check_id": "a" if index % 2 else "b",
                     "provider": "aws", "scope": f"{100000000000 + index % 3}/us-east-1",
                     "status": "FAIL" if index % 3 else "PASS",
                     "resource_id": f"resource-{35 - index:03d}",
                     **({"severity": "critical"} if index == 7 else {}),
                     **({"title": "Explicit title"} if index == 8 else {}),
                     **({"frameworks": ["Only this row"]} if index == 9 else {})})
    coverage = [{"status": "evaluated", "id": i} for i in range(550)]
    manifest = {"bundle_version": 1, "summary": {"snapshot_id": "synthetic"},
                "finding_chunks": [{"index_reference": "index"}],
                "coverage_chunks": ["coverage-0", "coverage-1", "coverage-2"],
                "coverage_chunk_counts": [250, 250, 50], "coverage_count": 550,
                "check_meta": {
                    "a": {"title": "Archived alpha", "remediation": "Reviewed action A", "service": "ec2",
                          "category": "exposure", "severity": "high", "description": "Archived description A"},
                    "b": {"title": "Archived beta", "remediation": "Reviewed action B", "service": "s3",
                          "category": "hardening", "severity": "medium", "description": "Archived description B"}},
                "check_frameworks": {"a": ["NIST 800-53"], "b": ["CIS AWS"]},
                "framework_filters": {}}
    artifacts = Artifacts({"manifest": manifest, "index": {"items": rows},
                           "coverage-0": {"items": coverage[:250]},
                           "coverage-1": {"items": coverage[250:500]},
                           "coverage-2": {"items": coverage[500:]}})
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, store=Store(), authenticator=Users(), artifacts=artifacts),
                    base_url="http://127.0.0.1:8000") as client:
        yield client, artifacts, rows, manifest


def route(suffix):
    return f"/api/scans/{SCAN}/{suffix}"


def test_counted_coverage_reads_only_overlapping_chunks_and_legacy_falls_back(api):
    client, artifacts, _, manifest = api
    response = client.get(route("coverage"), params={"offset": 300, "limit": 100},
                          headers={"Authorization": "Bearer alice"})
    assert response.status_code == 200
    assert [item["id"] for item in response.json()["items"]] == list(range(300, 400))
    assert response.json()["total"] == 550 and response.json()["next_offset"] == 400
    assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 1
    assert artifacts.reads["coverage-1"] == 1
    assert client.get(route("coverage"), params={"offset": 600, "limit": 100},
                      headers={"Authorization": "Bearer alice"}).json()["total"] == 550
    assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 1
    manifest.pop("coverage_chunk_counts")
    artifacts.reads.clear()
    legacy = client.get(route("coverage"), params={"offset": 300, "limit": 100},
                        headers={"Authorization": "Bearer alice"})
    assert legacy.json() == response.json()
    assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 3


def test_coverage_count_sidecar_fallback_mismatch_and_extra_target(api):
    client, artifacts, _, manifest = api
    headers = {"Authorization": "Bearer alice"}
    manifest["coverage_chunk_counts"] = [250]
    fallback = client.get(route("coverage"), params={"offset": 300, "limit": 100}, headers=headers)
    assert fallback.status_code == 200 and fallback.json()["total"] == 550
    assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 3
    for malformed in ([True, 250, 50], [-1, 501, 50], [250, 249, 50]):
        manifest["coverage_chunk_counts"] = malformed
        artifacts.reads.clear()
        response = client.get(route("coverage"), params={"offset": 300, "limit": 100}, headers=headers)
        assert response.status_code == 200 and response.json() == fallback.json()
        assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 3
    manifest["coverage_chunk_counts"] = [251, 249, 50]
    assert client.get(route("coverage"), params={"offset": 0, "limit": 1}, headers=headers).status_code == 409
    manifest["coverage_chunk_counts"] = [250, 250, 50]
    manifest["summary"]["snapshot_metadata"] = {"scan_coverage": [{
        "level": "credential_target", "status": "not_collected",
        "error_code": "duplicate_account_target", "account": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/reader"}]}
    artifacts.reads.clear()
    final = client.get(route("coverage"), params={"offset": 550, "limit": 1}, headers=headers)
    assert final.status_code == 200 and final.json()["total"] == 551
    assert final.json()["items"][0]["code"] == "duplicate_account_target"
    assert sum(artifacts.reads[ref] for ref in manifest["coverage_chunks"]) == 0


def test_findings_archived_fields_filters_facets_all_sorts_and_pages(api):
    client, _, rows, _ = api
    headers = {"Authorization": "Bearer alice"}
    base = client.get(route("findings"), params={"limit": 100}, headers=headers)
    assert base.status_code == 200
    values = base.json()
    assert values["total"] == len(rows)
    assert values["facets"] == {"services": ["ec2", "s3"], "statuses": ["FAIL", "PASS"],
                               "frameworks": ["CIS AWS", "NIST 800-53", "Only this row"]}
    assert all(item["description"].startswith("Archived description") for item in values["items"])
    all_rows = {item["id"]: item for item in values["items"]}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    for sort_by in ("severity", "title", "service", "account", "status", "resource_id"):
        for order in ("asc", "desc"):
            page = client.get(route("findings"), params={"sort_by": sort_by, "sort_order": order,
                                                           "offset": 7, "limit": 11}, headers=headers)
            assert page.status_code == 200, page.text
            assert page.json()["total"] == 36 and len(page.json()["items"]) == 11
            assert all(page_item == all_rows[page_item["id"]] for page_item in page.json()["items"])
            expected = sorted(all_rows.values(), key=lambda item: item["id"])
            if sort_by == "severity":
                expected.sort(key=lambda item: (severity_rank.get(item["severity"], 5), item["severity"]),
                              reverse=order == "desc")
            else:
                expected.sort(key=lambda item: str(
                    item.get("resource_name") or item.get("native_resource_id") or item.get("resource_id") or ""
                    if sort_by == "resource_id" else item.get(sort_by) or "").casefold(),
                    reverse=order == "desc")
            assert [item["id"] for item in page.json()["items"]] == [item["id"] for item in expected[7:18]]
            first = client.get(route("findings"), params={"sort_by": sort_by, "sort_order": order,
                                                            "limit": 7}, headers=headers).json()
            assert not set(item["id"] for item in first["items"]) & set(item["id"] for item in page.json()["items"])
    filters = {"categories": "exposure", "severity": "high", "status": "FAIL",
               "framework": "NIST 800-53", "limit": 100}
    filtered = client.get(route("findings"), params=filters, headers=headers).json()
    assert filtered["total"] == sum(
        item["category"] == "exposure" and item["severity"] == "high"
        and item["status"] == "FAIL" and "NIST 800-53" in item["frameworks"]
        for item in all_rows.values())
    search = client.get(route("findings"), params={"search": "Archived description A", "limit": 100},
                        headers=headers).json()
    assert {item["id"] for item in search["items"]} == {
        item["id"] for item in all_rows.values() if item["description"] == "Archived description A"}
    remediation_search = client.get(route("findings"), params={"search": "Reviewed action A", "limit": 100},
                                    headers=headers).json()
    assert {item["id"] for item in remediation_search["items"]} == {
        item["id"] for item in all_rows.values() if item["remediation"] == "Reviewed action A"}
    assert client.get(route("findings"), headers={"Authorization": "Bearer bob"}).status_code == 404


def test_legacy_inline_and_long_archived_title(api):
    client, artifacts, rows, manifest = api
    headers = {"Authorization": "Bearer alice"}
    manifest["check_meta"]["a"]["title"] = "A" * 500
    sorted_page = client.get(route("findings"), params={"sort_by": "title", "limit": 100}, headers=headers)
    assert sorted_page.status_code == 200
    titles = [item["title"].casefold() for item in sorted_page.json()["items"]]
    assert titles == sorted(titles)
    assert any(item["title"].endswith(" [Full value available in finding detail]")
               for item in sorted_page.json()["items"])
    artifacts.items["manifest"] = {"bundle_version": 0, "findings": copy.deepcopy(rows),
                                   "coverage": [{"id": 1, "status": "evaluated"}],
                                   "coverage_chunk_counts": [250, 250, 50],
                                   "coverage_chunks": ["coverage-0", "coverage-1", "coverage-2"],
                                   "coverage_count": 550}
    inline = client.get(route("findings"), params={"group_by": "resource_id", "limit": 100}, headers=headers)
    assert inline.status_code == 200
    assert inline.json()["total"] == len(rows)
    assert [item["id"] for item in inline.json()["items"]] == [
        item["id"] for item in sorted(rows, key=lambda item: (str(item["resource_id"]), item["id"]))]
    artifacts.reads.clear()
    assert client.get(route("coverage"), headers=headers).json()["total"] == 1
    assert sum(artifacts.reads[ref] for ref in ("coverage-0", "coverage-1", "coverage-2")) == 0
