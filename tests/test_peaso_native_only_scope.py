"""Automatic product admission excludes external contracts without changing evidence."""
import copy
import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.checks.native_only import exclusions
from peaso.snapshot import make_snapshot
from peaso.server import catalog_view


@pytest.mark.parametrize("check_id", sorted(exclusions()))
def test_external_contract_cannot_be_selected_for_collection_or_evaluation(check_id):
    check = next(check for check in CHECKS if check.id == check_id)
    snapshot = make_snapshot(check.provider, ["fixture"], [])
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.evaluate_snapshot(snapshot, checks=[check_id])
    with pytest.raises(ValueError, match="external policy or manual evidence"):
        engine.plan_collection({"connector": {"provider": check.provider}, "checks": [check_id]})


def test_all_public_selectors_and_framework_counts_use_active_scope():
    excluded = set(exclusions())
    assert excluded and excluded <= {check.id for check in CHECKS}
    full = engine.get_catalog()
    catalog_view.summary.cache_clear()
    catalog_view.frameworks_view.cache_clear()
    summary = catalog_view.summary()
    active = {check.id for check in engine._registry()}
    assert active.isdisjoint(excluded)
    assert not excluded.intersection(check["id"] for check in full["checks"])
    assert not excluded.intersection(check["id"] for check in summary["checks"])
    assert full["manual_requirements"] == []
    assert full["upstream_coverage"]["native_checks"] == len(active)
    for row in full["framework_versions"]:
        assert not excluded.intersection(row["native_check_ids"])
        assert row["supported_native_checks"] == len(row["native_check_ids"])
    for provider in ("aws", "gcp", "azure", "k8s"):
        _, default = engine._selection(provider, None, None, None)
        _, framework = engine._selection(provider, None, None, ["HackTricks Cloud Best Practices"])
        assert not excluded.intersection(c.id for c in default + framework)


@pytest.mark.parametrize("provider,check,kind", [
    ("aws", "aws.ec2.imdsv2", "instance"),
    ("gcp", "gcp.storage.uniform_access", "bucket"),
    ("azure", "azure.storage.https_only", "storage_account"),
    ("k8s", "k8s.pod.no_privileged_containers", "pod"),
])
@pytest.mark.parametrize("state,expected", [("denied", "DENIED"), ("not_collected", "UNKNOWN")])
def test_native_read_gaps_are_not_excluded_or_reported_as_pass(provider, check, kind, state, expected):
    assert check not in exclusions()
    snapshot = make_snapshot(provider, ["fixture"], [{"type": kind, "scope": "fixture", "status": state, "items": []}])
    original = copy.deepcopy(snapshot)
    report = engine.evaluate_snapshot(snapshot, checks=[check], categories=["hardening"])
    assert snapshot == original
    assert report["findings"][0]["status"] == expected
    assert not report["stats"]["coverage_complete"]


def test_host_file_attestations_are_not_automatic_inventories():
    full = engine.get_catalog()
    assert "file_metadata" not in full["inventories"]["k8s"]
    assert "file_metadata" not in engine.plan_collection({"connector": {"provider": "k8s"}})
    with pytest.raises(ValueError, match="inventories must be supported"):
        engine.plan_collection({"connector": {"provider": "k8s", "options": {"inventories": ["file_metadata"]}}})
