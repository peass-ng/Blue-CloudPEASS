"""Registered GCP Data Access checks require a unique project-root read."""

import copy

import pytest

from peaso.checks.gcp_data_access import CHECK_SERVICES
from peaso.collectors import gcp
from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from test_peaso_gcp_data_access import ORG, PROJECT, config, owner, policy, report


def _findings(check_id, base, items):
    collection = {**base["collections"][0], "items": items}
    snapshot = make_snapshot("gcp", base["scopes"], [collection], metadata=base["metadata"])
    result = evaluate_snapshot(snapshot, checks=[check_id], categories=["hardening"])
    return [finding for finding in result["findings"] if finding["check_id"] == check_id
            and not finding["resource_id"].startswith("inventory:")]


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_mixed_or_contradictory_root_collection_cannot_pass(check_id):
    service = CHECK_SERVICES[check_id]
    _, base = report(check_id, project=[config(service, "DATA_READ"),
                                        config(service, "DATA_WRITE")], ancestry=False)
    root = copy.deepcopy(base["collections"][0]["items"][0])
    assert [row["status"] for row in _findings(check_id, base, [root])] == ["PASS"]

    foreign = copy.deepcopy(root)
    foreign["name"] = "projects/foreign"
    mixed = _findings(check_id, base, [root, foreign])
    assert "PASS" not in {row["status"] for row in mixed}
    assert any(row["evidence"]["reason"] == "project-root IAM policy collection is not unique"
               for row in mixed)

    contrary = copy.deepcopy(root)
    contrary["effectiveAuditConfigs"][0]["auditConfigs"] = []
    assert {row["status"] for row in _findings(check_id, base, [contrary])} == {"FAIL"}
    for items in ([contrary, root], [root, contrary]):
        contradictory = _findings(check_id, base, items)
        assert {row["status"] for row in contradictory} == {"UNKNOWN"}
        assert {row["evidence"]["reason"] for row in contradictory} == {
            "project-root IAM policy collection is not unique"}


def test_snapshot_rejects_duplicate_project_collection_envelopes():
    check_id = next(iter(CHECK_SERVICES))
    service = CHECK_SERVICES[check_id]
    _, base = report(check_id, project=[config(service, "DATA_READ"),
                                        config(service, "DATA_WRITE")], ancestry=False)
    with pytest.raises(ValueError, match="duplicate collection type/scope"):
        make_snapshot("gcp", base["scopes"], [base["collections"][0]] * 2,
                      metadata=base["metadata"])


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_project_root_with_collected_resource_policy_peer_keeps_root_verdict(check_id):
    service = CHECK_SERVICES[check_id]
    _, base = report(check_id, project=[config(service, "DATA_READ"),
                                        config(service, "DATA_WRITE")], ancestry=False)
    root = copy.deepcopy(base["collections"][0]["items"][0])
    resource = {"name": "//storage.googleapis.com/projects/_/buckets/fixture",
                "assetType": "storage.googleapis.com/Bucket", "bindings": []}
    collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
    collector.needed = {"iam_policy"}
    collector.ancestry = {PROJECT: []}
    collector.collections = {("iam_policy", PROJECT): {"items": [root, resource]}}
    collector.annotate_effective_audit()
    assert root["_coverage"]["effectiveAuditConfigs"]["status"] == "collected"
    findings = _findings(check_id, base, collector.collections[("iam_policy", PROJECT)]["items"])
    assert {row["status"] for row in findings} == {"PASS", "NOT_APPLICABLE"}
    assert next(row for row in findings if row["status"] == "PASS")["scope"] == PROJECT

    incomplete = copy.deepcopy(root)
    incomplete["effectiveAuditConfigs"][0]["auditConfigs"] = []
    assert {row["status"] for row in _findings(check_id, base, [incomplete, resource])} == {
        "FAIL", "NOT_APPLICABLE"}
    for uncertain in ({"bindings": []},
                      {"name": "//cloudresourcemanager.googleapis.com/projects/fixture",
                       "assetType": "cloudresourcemanager.googleapis.com/Project"}):
        assert "PASS" not in {row["status"] for row in _findings(check_id, base, [root, uncertain])}


@pytest.mark.parametrize("check_id", tuple(CHECK_SERVICES))
def test_duplicate_ancestor_roots_never_supply_complete_effective_audit(check_id):
    service = CHECK_SERVICES[check_id]
    good = policy(ORG, [config(service, "DATA_READ"), config(service, "DATA_WRITE")])
    bad = policy(ORG, [])
    for ancestor_items in ([bad, good], [good, bad]):
        collector = gcp.GCPCollector.__new__(gcp.GCPCollector)
        collector.needed = {"iam_policy"}
        collector.ancestry = {PROJECT: [{"resourceId": {"type": "organization", "id": "34"}}]}
        collector.collections = {
            ("iam_policy", PROJECT): {"items": [policy(PROJECT, [])]},
            ("iam_policy", ORG): {"items": copy.deepcopy(ancestor_items)},
        }
        collector.annotate_effective_audit()
        item = collector.collections[("iam_policy", PROJECT)]["items"][0]
        snapshot = make_snapshot("gcp", [PROJECT], [{"type": "iam_policy", "scope": PROJECT,
            "status": "collected", "items": [item]}],
            metadata={OPTION: normalize_owner_policy([owner(service)], [PROJECT])})
        result = evaluate_snapshot(snapshot, checks=[check_id], categories=["hardening"])
        findings = [row for row in result["findings"] if row["check_id"] == check_id
                    and not row["resource_id"].startswith("inventory:")]
        assert {row["status"] for row in findings} == {"UNKNOWN"}
        assert item["_coverage"]["effectiveAuditConfigs"]["malformed_scopes"] == [ORG]
