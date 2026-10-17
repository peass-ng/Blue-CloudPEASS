"""Independent integration acceptance for snapshot integrity and offline selection."""
import copy
import json
import socket
import subprocess

import pytest

from peaso.engine import catalog, evaluate_snapshot, hydrate_frameworks
from peaso.snapshot import make_snapshot, validate


def inventory(provider, status="collected"):
    kinds = {"aws": ("bucket", {"Name": "peaso-test-inert", "PublicAccessBlock": {"BlockPublicAcls": True}}),
             "gcp": ("bucket", {"name": "peaso-test-inert", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}),
             "azure": ("storage_account", {"id": "/subscriptions/test/resourceGroups/peaso-test/providers/Microsoft.Storage/storageAccounts/inert", "properties": {"allowBlobPublicAccess": False}}),
             "k8s": ("pod", {"metadata": {"name": "peaso-test-inert", "namespace": "peaso-test"}, "spec": {"containers": [{"name": "inert", "image": "registry.k8s.io/pause:3.10", "securityContext": {"runAsNonRoot": True}}]}})}
    kind, item = kinds[provider]
    return make_snapshot(provider, ["peaso-test-scope"], [{"type": kind, "scope": "peaso-test-scope", "service": kind,
        "status": status, "items": [item] if status in ("collected", "partial") else [],
        **({"error": {"code": "AccessDenied"}} if status == "denied" else {})}], created_at="2026-10-10T00:00:00Z")


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_offline_evaluation_is_repeatable_and_immutable(provider, monkeypatch):
    snapshot = inventory(provider)
    before = copy.deepcopy(snapshot)
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline evaluation attempted I/O")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    first = evaluate_snapshot(snapshot)
    second = evaluate_snapshot(json.loads(json.dumps(snapshot)))
    assert first == second
    assert snapshot == before
    assert first["snapshot_id"] == snapshot["snapshot_id"]
    assert set(first) >= {"resources", "findings", "coverage", "graphs", "stats"}
    assert first["stats"]["coverage_complete"] is False
    assert any(row["status"] == "unknown" for row in first["coverage"] if row["level"] == "check")


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_category_check_and_framework_filters_use_same_snapshot(provider):
    snapshot = inventory(provider)
    full = evaluate_snapshot(snapshot)
    provider_checks = [check for check in catalog()["checks"] if check["provider"] == provider]
    assert provider_checks, "Every provider must publish native checks"
    target = provider_checks[0]
    filtered = evaluate_snapshot(snapshot, categories=[target["category"]], checks=[target["id"]], frameworks=[target["frameworks"][0]])
    assert filtered["snapshot_id"] == full["snapshot_id"]
    assert filtered["resources"] == full["resources"]
    assert filtered["findings"]
    assert {row["check_id"] for row in filtered["findings"]} == {target["id"]}
    assert {row["category"] for row in hydrate_frameworks(filtered)["findings"]} == {target["category"]}
    assert filtered["stats"]["check_count"] == 1
    # Public empty selectors mean defaults, matching API model defaults.
    assert evaluate_snapshot(snapshot, categories=[], checks=[], frameworks=[]) == full


@pytest.mark.parametrize("status,expected", [("denied", "DENIED"), ("empty", "EMPTY"), ("not_collected", "UNKNOWN"), ("timeout", "UNKNOWN")])
def test_unavailable_inventory_never_becomes_resource_pass(status, expected):
    report = evaluate_snapshot(inventory("aws", status), categories=["hardening"])
    findings = [row for row in report["findings"] if row["evidence"].get("collection_status") == status]
    assert findings
    assert {row["status"] for row in findings} == {expected}
    assert report["stats"]["coverage_complete"] is False


def test_tampering_and_duplicate_inventory_are_rejected():
    snapshot = inventory("aws")
    modified = copy.deepcopy(snapshot)
    modified["collections"][0]["items"][0]["Name"] = "changed"
    with pytest.raises(ValueError, match="digest"):
        validate(modified)
    duplicate = copy.deepcopy(snapshot)
    duplicate["collections"].append(copy.deepcopy(duplicate["collections"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        validate(duplicate)


@pytest.mark.parametrize("selection", [{"categories": ["invalid"]}, {"checks": ["invalid"]}, {"frameworks": ["invalid"]}])
def test_unknown_filters_fail_explicitly(selection):
    with pytest.raises(ValueError):
        evaluate_snapshot(inventory("aws"), **selection)
