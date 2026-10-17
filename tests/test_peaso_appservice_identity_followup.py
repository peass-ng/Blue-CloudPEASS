"""Focused private collector-to-native-evaluator evidence; no cloud requests."""
import importlib.util
from pathlib import Path

import pytest

from peaso.checks import evaluate_check
from peaso.checks.facts import MemoIndex
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot
from peaso.collectors.azure import _Reader

ROOT = Path(__file__).resolve().parent
SITE = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Web/sites/site1"
UAI = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"


from peaso.checks import azure_appservice_identity_followup as CANDIDATE
from peaso.collectors import azure_appservice_identity_followup as PRODUCER


def snapshot(identity, *, child_status="collected", detail=True, site_kind="app", child_id=None,
             provenance=None, parent_id=SITE, detail_kind="app"):
    site = {"id": SITE, "kind": site_kind, "type": "Microsoft.Web/sites", "properties": {}}
    child = {"id": child_id or SITE + "/identityDetail", "parent_id": parent_id, "kind": detail_kind,
             "identity": identity, "_provenance": provenance or {"representation": "full", "source_operation": "get", "read_only": True}}
    collections = {"app_service": [{"type": "app_service", "scope": "/subscriptions/sub1", "status": "collected", "items": [site]}],
                   "app_service_identity_detail": [{"type": "app_service_identity_detail", "scope": "/subscriptions/sub1",
                                                    "status": child_status, "items": [child] if detail else []}]}
    index = MemoIndex({"context": {"provider": "azure", "scope": "/subscriptions/sub1"},
                       "collections": collections,
                       "app_service": [{"provider": "azure", "type": "app_service", "scope": "/subscriptions/sub1", "data": site}],
                       "app_service_identity_detail": [{"provider": "azure", "type": "app_service_identity_detail", "scope": "/subscriptions/sub1", "data": child}] if detail else []})
    return site, index


@pytest.mark.parametrize("identity, expected", [
    ({"type": "None"}, "FAIL"),
    ({"type": "SystemAssigned", "principalId": "12345678-1234-1234-1234-123456789abc"}, "PASS"),
    ({"type": "SystemAssigned", "principalId": "ABCDEF12-3456-789A-BCDE-F0123456789A"}, "PASS"),
    ({"type": "UserAssigned", "userAssignedIdentities": {UAI: None}}, "PASS"),
    ({"type": "SystemAssigned", "principalId": None}, "UNKNOWN"),
    ({"type": "SystemAssigned", "principalId": "-" * 36}, "UNKNOWN"),
    ({"type": "SystemAssigned", "principalId": "0" * 8 + "-" + "0" * 4 + "-" + "0" * 4 + "-" + "0" * 4 + "-" + "0" * 12}, "UNKNOWN"),
    ({"type": "SystemAssigned", "principalId": "123456781234-1234-1234-123456789abc"}, "UNKNOWN"),
    ({"type": "SystemAssigned", "principalId": "12345678-1234-1234-1234-123456789abc", "userAssignedIdentities": {UAI: None}}, "UNKNOWN"),
    ({"type": "UserAssigned", "userAssignedIdentities": {}}, "UNKNOWN"),
    ({"type": "UserAssigned", "userAssignedIdentities": {UAI: None}, "principalId": "12345678-1234-1234-1234-123456789abc"}, "UNKNOWN"),
    ({"type": "SystemAssigned, UserAssigned", "principalId": "12345678-1234-1234-1234-123456789abc", "userAssignedIdentities": {UAI: None}}, "PASS"),
    ({"type": "SystemAssigned, UserAssigned", "principalId": "-" * 36, "userAssignedIdentities": {UAI: None}}, "UNKNOWN"),
    ({"type": "None", "principalId": "12345678-1234-1234-1234-123456789abc"}, "UNKNOWN"),
    ({"type": "Alien"}, "UNKNOWN"),
    ({}, "UNKNOWN"),
])
def test_existing_registry_contract(identity, expected):
    site, index = snapshot(identity)
    assert evaluate_check(CANDIDATE.CHECK_ID, site, index)[0] == expected


@pytest.mark.parametrize("change", [
    {"child_status": "denied"}, {"child_status": "partial"}, {"detail": False},
    {"child_id": "/subscriptions/other/resourceGroups/rg1/providers/Microsoft.Web/sites/site1/identityDetail"},
    {"parent_id": "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Web/sites/other"},
    {"provenance": {"representation": "list", "source_operation": "list", "read_only": True}},
    {"detail_kind": ""},
])
def test_unavailable_and_foreign_never_pass_or_fail(change):
    site, index = snapshot({"type": "None"}, **change)
    assert evaluate_check(CANDIDATE.CHECK_ID, site, index)[0] == "UNKNOWN"


def test_duplicate_child_fails_closed():
    site, index = snapshot({"type": "None"})
    index["collections"]["app_service_identity_detail"][0]["items"].append(dict(index["collections"]["app_service_identity_detail"][0]["items"][0]))
    index["app_service_identity_detail"].append(dict(index["app_service_identity_detail"][0]))
    assert evaluate_check(CANDIDATE.CHECK_ID, site, index)[0] == "UNKNOWN"


def test_opt_in_producer_uses_one_bounded_get_and_keeps_only_identity_metadata():
    calls = []
    class Reader:
        def call(self, request, url):
            return request(url)
    def request(url):
        calls.append(url)
        return {"id": SITE, "type": "Microsoft.Web/sites", "kind": "app", "identity":
                {"type": "UserAssigned", "userAssignedIdentities": {UAI: {"clientId": "sensitive"}}},
                "properties": {"siteConfig": {"appSettings": [{"value": "secret"}]}}}
    job = PRODUCER.site_identity_job(Reader(), request, "https://management.azure.com", {"id": SITE})
    assert job[:3] == ("app_service_identity_detail", "/subscriptions/sub1", "Microsoft.Web")
    rows = list(job[3]())
    assert calls == ["https://management.azure.com" + SITE + "?api-version=2025-03-01"]
    assert rows[0][0]["identity"] == {"type": "UserAssigned", "userAssignedIdentities": {UAI: None}}
    assert rows[0][0]["kind"] == "app"
    assert "properties" not in rows[0][0]


def test_producer_rejects_foreign_detail_without_values():
    class Reader:
        def call(self, request, url):
            return {"id": SITE + "/foreign", "type": "Microsoft.Web/sites", "identity": {"type": "None"}}
    job = PRODUCER.site_identity_job(Reader(), lambda url: None, "https://management.azure.com", {"id": SITE})
    with pytest.raises(ValueError, match="foreign"):
        list(job[3]())


@pytest.mark.parametrize("identity, expected", [
    ({"type": "None"}, "FAIL"),
    ({"type": "SystemAssigned", "principalId": "12345678-1234-1234-1234-123456789abc"}, "PASS"),
    ({}, "UNKNOWN"),
])
def test_actual_snapshot_engine_and_aggregate_coverage(identity, expected):
    site, index = snapshot(identity)
    source = index["collections"]
    collections = [dict(collection, service="Microsoft.Web") for rows in source.values() for collection in rows]
    report = evaluate_snapshot(make_snapshot("azure", ["/subscriptions/sub1"], collections), checks=[CANDIDATE.CHECK_ID])
    findings = [row for row in report["findings"] if row["check_id"] == CANDIDATE.CHECK_ID]
    coverage = [row for row in report["coverage"] if row.get("check_id") == CANDIDATE.CHECK_ID]
    assert len(findings) == 1 and findings[0]["status"] == expected, findings[0]["evidence"] if findings else findings
    assert len(coverage) == 1 and coverage[0]["by_status"] == {expected: 1}


@pytest.mark.parametrize("denied,principal,expected", [
    (False, "12345678-1234-1234-1234-123456789abc", "PASS"),
    (False, "ABCDEF12-3456-789A-BCDE-F0123456789A", "PASS"),
    (False, "-" * 36, "UNKNOWN"),
    (False, "00000000-0000-0000-0000-000000000000", "UNKNOWN"),
    (True, "12345678-1234-1234-1234-123456789abc", "UNKNOWN"),
])
def test_reader_job_to_snapshot_to_existing_engine(denied, principal, expected):
    site = {"id": SITE, "type": "Microsoft.Web/sites", "kind": "app", "properties": {}}
    parent = {"type": "app_service", "scope": "/subscriptions/sub1", "service": "Microsoft.Web", "status": "collected", "items": [site]}
    reader = _Reader({"concurrency": 1, "retries": 0})
    def request(url):
        if denied:
            raise PermissionError("denied")
        return {"id": SITE, "type": "Microsoft.Web/sites", "kind": "app", "identity":
                {"type": "SystemAssigned", "principalId": principal},
                "properties": {"siteConfig": {"appSettings": [{"value": "secret"}]}}}
    reader.run([PRODUCER.site_identity_job(reader, request, "https://management.azure.com", site)])
    assert reader.collections[0]["scope"] == "/subscriptions/sub1"
    assert "secret" not in str(reader.collections)
    report = evaluate_snapshot(make_snapshot("azure", ["/subscriptions/sub1"], [parent, *reader.collections]),
                               checks=[CANDIDATE.CHECK_ID])
    findings = [row for row in report["findings"] if row["check_id"] == CANDIDATE.CHECK_ID]
    assert len(findings) == 1 and findings[0]["status"] == expected
