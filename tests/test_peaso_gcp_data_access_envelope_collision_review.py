# Historical archived-check predicate/collector contract; product selection rejects these IDs.
"""A duplicate hierarchy root must survive collection as ambiguity."""
from threading import Lock

import pytest

from peaso.collectors import gcp
from tests.gcp_archived_native_contract import evaluate_historical_snapshot
from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
from peaso.snapshot import make_snapshot
from test_peaso_gcp_data_access import ORG, PROJECT, config, owner, policy
from peaso.checks.gcp_data_access import CHECK_SERVICES


def test_conflicting_root_peers_in_live_envelope_cannot_pass():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.lock = Lock()
    collector.max_items = None
    collector.seen_items = set()
    collector.total_items = 0
    collector.read_time = "2026-10-17T00:00:00Z"
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    good = {"name": PROJECT, "bindings": [], "auditConfigs": [
        config(service, "DATA_READ"), config(service, "DATA_WRITE")], "_representation": "full"}
    contrary = {"name": PROJECT, "assetType": "cloudresourcemanager.googleapis.com/Project",
                "bindings": [], "auditConfigs": []}
    envelope = collector.envelope("iam_policy", PROJECT, "iam/cloudasset",
        lambda: iter([([good], "direct-request"), ([contrary], "cai-request")]))
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}


def test_unreadable_root_audit_configs_cannot_pass_after_annotation():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "auditConfigs": [config(service, "DATA_READ"),
        config(service, "DATA_WRITE")], "_coverage": {"auditConfigs": {"status": "denied"}},
        "_provenance": {"source_requests": ["direct-request"]}}
    envelope = {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [root]}
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}


@pytest.mark.parametrize("field", ["name", "assetType", "_representation"])
def test_unreadable_resource_policy_identity_cannot_certify_unique_root(field):
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "auditConfigs": [config(service, "DATA_READ"),
        config(service, "DATA_WRITE")], "_provenance": {"source_requests": ["direct-request"]}}
    peer = {"name": "//storage.googleapis.com/projects/_/buckets/fixture",
        "assetType": "storage.googleapis.com/Bucket", "bindings": [],
        "_coverage": {field: {"status": "denied"}}}
    envelope = {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [root, peer]}
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert "PASS" not in {row["status"] for row in findings}


def test_canonical_cai_project_view_remains_ambiguous_without_number_binding():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "auditConfigs": [config(service, "DATA_READ"),
        config(service, "DATA_WRITE")], "_provenance": {"source_requests": ["direct-request"]}}
    cai = {"name": "//cloudresourcemanager.googleapis.com/projects/12345",
        "assetType": "cloudresourcemanager.googleapis.com/Project",
        "project": "projects/12345", "bindings": []}
    envelope = {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [root, cai]}
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "partial"


def test_partial_ancestor_envelope_cannot_prove_complete_chain():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: [{"resourceId": {"type": "organization", "id": "34"}}]}
    project = policy(PROJECT, [])
    ancestor = policy(ORG, [config(service, "DATA_READ"), config(service, "DATA_WRITE")])
    collector.collections = {
        ("iam_policy", PROJECT): {"items": [project], "status": "collected", "coverage_status": "collected"},
        ("iam_policy", ORG): {"items": [ancestor], "status": "partial", "coverage_status": "partial"},
    }
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [{"type": "iam_policy", "scope": PROJECT,
        "status": "collected", "items": [project]}],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}


@pytest.mark.parametrize("marker,include_value", [
    (None, True), ({"status": "empty"}, True), ({"status": "collected"}, False),
])
def test_other_unavailable_root_audit_config_markers_remain_unknown(marker, include_value):
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "_coverage": {"auditConfigs": marker},
        "_provenance": {"representation": "full", "source_requests": ["direct-request"]}}
    if include_value:
        root["auditConfigs"] = [config(service, "DATA_READ"), config(service, "DATA_WRITE")]
    envelope = {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [root]}
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"UNKNOWN"}


def test_identical_repeated_root_page_keeps_complete_authority():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.lock = Lock()
    collector.max_items = None
    collector.seen_items = set()
    collector.total_items = 0
    collector.read_time = "2026-10-17T00:00:00Z"
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "bindings": [], "auditConfigs": [
        config(service, "DATA_READ"), config(service, "DATA_WRITE")], "_representation": "full"}
    envelope = collector.envelope("iam_policy", PROJECT, "iam/cloudasset",
        lambda: iter([([root], "page-1"), ([dict(root)], "page-2")]))
    assert envelope["status"] == "collected" and len(envelope["items"]) == 1
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {"PASS"}


@pytest.mark.parametrize("provenance,asset_type,wanted", [
    ({"representation": "full", "source_requests": ["direct"]}, None, "FAIL"),
    ({"source_requests": ["legacy"]}, None, "FAIL"),
    ({"source_requests": ["cai"]}, "cloudresourcemanager.googleapis.com/Project", "UNKNOWN"),
])
def test_omitted_root_audit_configs_need_full_or_legacy_authority(provenance, asset_type, wanted):
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.ancestry_source_requests = {}
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    root = {"name": PROJECT, "_provenance": provenance}
    if asset_type:
        root["assetType"] = asset_type
    envelope = {"type": "iam_policy", "scope": PROJECT, "status": "collected", "items": [root]}
    collector.collections = {("iam_policy", PROJECT): envelope}
    collector.annotate_effective_audit()
    snapshot = make_snapshot("gcp", [PROJECT], [envelope],
        metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
    findings = [row for row in evaluate_historical_snapshot(snapshot, checks=[check_id])["findings"]
        if row["check_id"] == check_id and not row["resource_id"].startswith("inventory:")]
    assert {row["status"] for row in findings} == {wanted}
