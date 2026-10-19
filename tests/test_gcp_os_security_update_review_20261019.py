"""Native read-only OS Config production -> pure assessment consumer.

Reuses tests.test_peaso_gcp_os_patch_native.API's native VM/OS Config transport.
No cloud credentials, OS patch actions, package content or owner policy inputs.
"""
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from peaso.checks.facts import MemoIndex
from peaso.checks.gcp_os_security_update_review_20261019 import DEPENDENCIES, evaluate
from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.engine import _index
from peaso.snapshot import resources
from tests.test_peaso_gcp_os_patch_native import API, SCOPE

NUMBER = "987654321"
CAPTURED = "2026-10-19T12:00:00.000000000Z"


class AssessmentAPI(API):
    def __init__(self, mode):
        super().__init__(mode)
        self.now = datetime(2026, 10, 19, 11, tzinfo=timezone.utc)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, deepcopy(kwargs)))
        data, rid = super().request(method, url, **kwargs)
        path = urlsplit(url).path
        if path in ("/v3/" + SCOPE, "/v3/projects/" + NUMBER):
            data.update(name="projects/" + NUMBER, projectId="demo-project")
            if self.mode == "foreign_project_metadata":
                data["projectId"] = "another-project"
        elif path.endswith("/aggregated/instances"):
            vm = data["items"]["zones/us-central1-a"]["instances"][0]
            if self.mode == "foreign_vm_zone":
                vm["zone"] = vm["zone"].replace("demo-project", "foreign-project")
            if self.mode == "contradictory_vm_self_link":
                vm["selfLink"] = "https://www.googleapis.com/compute/v1/" + SCOPE + "/zones/us-central1-b/instances/vm"
            if self.mode == "vm_partial":
                data["warning"] = {"code": "PARTIAL"}
            if self.mode == "duplicate_vm_subject":
                data["items"]["zones/us-central1-a"]["instances"].append({**vm, "name": "other"})
        elif path.endswith("/vulnerabilityReport"):
            if self.mode in ("numeric_report", "numeric_scope"):
                data["name"] = data["name"].replace(SCOPE, "projects/" + NUMBER)
            if self.mode in ("fixable", "low_fix", "no_fix", "omitted_fix", "unknown_severity", "malformed_reference", "stripped_cve"):
                data["vulnerabilities"] = [{"details": {"severity": "LOW" if self.mode == "low_fix" else "UNKNOWN" if self.mode == "unknown_severity" else "HIGH",
                    "cve": "CVE-2026-12345", "description": "synthetic private-detail marker"},
                    "items": [{}] if self.mode == "omitted_fix" else [{"availableInventoryItemId": "" if self.mode == "no_fix" else 17 if self.mode == "malformed_reference" else "available-package"}]}]
            if self.mode == "numeric_report":
                data["vulnerabilities"] = [{"details": {"severity": "HIGH"}, "items": [{"availableInventoryItemId": "available-package"}]}]
            if self.mode == "foreign_zone_report":
                data["name"] = data["name"].replace("us-central1-a", "us-central1-b")
            if self.mode == "empty_report_object":
                data = {}
            if self.mode == "missing_update_time":
                data.pop("updateTime")
            if self.mode == "malformed_update_time":
                data["updateTime"] = "2026-10-19 11:00:00"
            if self.mode == "report_future":
                data["updateTime"] = "2026-10-19T13:00:00Z"
            if self.mode == "nanosecond_future":
                data["updateTime"] = "2026-10-19T12:00:00.000000001Z"
            if self.mode == "report_partial":
                data["warning"] = {"code": "PARTIAL"}
            if self.mode == "old_assessment":
                data["updateTime"] = "2020-01-01T00:00:00Z"
        return data, rid


def native_case(mode):
    api = AssessmentAPI(mode)
    selected_scope = "projects/" + NUMBER if mode == "numeric_scope" else SCOPE
    connector = {"provider": "gcp", "scopes": [selected_scope], "options": {
        "resource_iam": False, "metrics_scopes": False, "include_inherited": False, "concurrency": 1}}
    collector = GCPCollector(connector, requirements=list(DEPENDENCIES), transport=api)
    collector.read_time = CAPTURED
    snapshot = collector.collect()
    index = _index(snapshot, resources(snapshot))
    index["context"] = {"provider": "gcp", "scope": selected_scope, "created_at": snapshot["created_at"],
                        "snapshot_id": snapshot["snapshot_id"], "metadata": snapshot["metadata"]}
    item = index["instance"][0]["data"] if index["instance"] else {}
    status, evidence = evaluate(item, MemoIndex(index))
    assert all(method == "GET" for method, _, _ in api.requests)
    assert all(not url.endswith(("/inventory", ":execute")) for _, url, _ in api.requests)
    assert not {"compliance_policy", "sw53_policy"}.intersection(snapshot["metadata"])
    return snapshot, index, item, status, evidence


@pytest.mark.parametrize("mode,expected", [
    ("fixable", "FAIL"), ("low_fix", "FAIL"), ("no_fix", "PASS"), ("omitted_fix", "PASS"),
    ("empty", "PASS"), ("old_assessment", "PASS"), ("numeric_report", "FAIL"), ("numeric_scope", "PASS"),
    ("report_denied", "UNKNOWN"), ("foreign_report", "UNKNOWN"), ("foreign_project_report", "UNKNOWN"),
    ("foreign_zone_report", "UNKNOWN"), ("foreign_project_metadata", "UNKNOWN"),
    ("foreign_vm_zone", "UNKNOWN"), ("contradictory_vm_self_link", "UNKNOWN"),
    ("unknown_severity", "UNKNOWN"), ("malformed_reference", "UNKNOWN"),
    ("empty_report_object", "UNKNOWN"), ("missing_update_time", "UNKNOWN"), ("malformed_update_time", "UNKNOWN"),
    ("report_future", "UNKNOWN"), ("nanosecond_future", "UNKNOWN"), ("report_partial", "UNKNOWN"),
    ("vm_partial", "UNKNOWN"), ("duplicate_vm_subject", "UNKNOWN"), ("malformed_report", "UNKNOWN"),
])
def test_native_response_to_assessment_consumer(mode, expected):
    _, _, _, status, evidence = native_case(mode)
    assert status == expected, evidence
    assert "assessment" in evidence["claim"]
    if status in ("PASS", "FAIL"):
        assert evidence["assessment_time"]
        assert evidence["instance_id"] == "123" and evidence["project_number"] == NUMBER
        assert "current patch compliance and freshness are not assessed" in evidence["scope"]
        assert evidence["fixable_finding_count"] == int(status == "FAIL")


def test_native_projection_strips_cve_details_without_inventing_dates_or_distinct_cves():
    snapshot, _, _, status, evidence = native_case("stripped_cve")
    report = next(c for c in snapshot["collections"] if c["type"] == "os_vulnerability_report")["items"][0]
    assert report["vulnerabilities"] == [{"severity": "HIGH", "items": [{"availableInventoryItemId": "available-package"}]}]
    assert status == "FAIL" and evidence["fixable_finding_count"] == 1
    assert "private-detail marker" not in str(snapshot)
    assert not {"cve", "publishedTime", "installedTime", "package_age"}.intersection(evidence)


@pytest.mark.parametrize("mutation", ["empty_collection", "ambiguous_report", "foreign_provenance", "foreign_request", "duplicate_request",
    "mismatched_projection", "empty_item_list", "unknown_model", "future_capture", "denied_field"])
def test_incomplete_or_ambiguous_collected_subject_cannot_create_pass(mutation):
    _, index, item, status, _ = native_case("empty")
    assert status == "PASS"
    index = deepcopy(index)
    envelope = index["collections"]["os_vulnerability_report"][0]
    report = index["os_vulnerability_report"][0]["data"]
    if mutation == "empty_collection":
        envelope.update(status="empty", coverage_status="empty", items=[])
        index["os_vulnerability_report"] = []
    elif mutation == "ambiguous_report":
        envelope["items"].append(deepcopy(report))
        index["os_vulnerability_report"].append(deepcopy(index["os_vulnerability_report"][0]))
    elif mutation == "foreign_provenance":
        report["_provenance"]["scope"] = "projects/foreign"
    elif mutation == "foreign_request":
        report["_provenance"]["source_requests"] = ["other-source"]
    elif mutation == "duplicate_request":
        index["context"]["metadata"]["source_requests"].append(deepcopy(index["context"]["metadata"]["source_requests"][0]))
    elif mutation == "mismatched_projection":
        envelope["items"] = []
    elif mutation == "empty_item_list":
        report["vulnerabilities"] = [{"severity": "HIGH", "items": []}]
    elif mutation == "unknown_model":
        report["native_model"] = "other"
    elif mutation == "future_capture":
        report["_provenance"]["collected_at"] = "2027-01-01T00:00:00Z"
    else:
        report.setdefault("_coverage", {})["vulnerabilities"] = {"status": "denied"}
    # Keep the native envelope and wrapper projection consistent except in the
    # deliberate mismatch case. This exercises semantic joins beyond equality.
    if mutation not in ("empty_collection", "mismatched_projection", "ambiguous_report"):
        envelope["items"] = [deepcopy(report)]
    actual, evidence = evaluate(item, MemoIndex(index))
    assert actual == "UNKNOWN", evidence


def test_install_is_idempotent_and_loads_full_native_cases(monkeypatch):
    import peaso.checks as registry
    from peaso.checks import fixtures
    from peaso.checks import gcp_os_security_update_review_20261019 as check
    from peaso.finding_types import type_ids
    assert check.DECLARATION['finding_type'] == 'vulnerabilities'
    assert check.DECLARATION['finding_type'] in type_ids()
    assert check.DECLARATION['title'] == 'VM assessment has no fixable known vulnerabilities'
    monkeypatch.setattr(registry, 'CHECKS', [c for c in registry.CHECKS if c.id != check.CANDIDATE_ID])
    monkeypatch.setattr(fixtures, 'CASES', {k: v for k, v in fixtures.CASES.items() if k != check.CANDIDATE_ID})
    check.install()
    check.install()
    registered, = [c for c in registry.CHECKS if c.id == check.CANDIDATE_ID]
    assert registered.severity == 'high' and set(registered.dependencies) == set(DEPENDENCIES)
    cases = fixtures.CASES[check.CANDIDATE_ID]
    for label in ('pass', 'fail', 'unknown'):
        status, evidence = evaluate(cases[label], MemoIndex(cases[label + '_index']))
        assert status == label.upper()
        if status != 'UNKNOWN':
            assert evidence['assessment_time'] in evidence['observed']
            assert str(evidence['fixable_finding_count']) in evidence['observed']
            assert len(evidence['observed'].split('. ')) == 2
