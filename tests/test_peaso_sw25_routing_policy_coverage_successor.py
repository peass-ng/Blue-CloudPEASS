"""Registered alert-routing policy coverage boundaries using native declarations."""
from __future__ import annotations

import pytest

from peaso.collectors.azure_alert_routing_native import CONTRACTS, project
from peaso.checks.compliance_new_sw25_facts import ROUTING_ID
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_alert_routing_native import SCOPE, native


def verdict(metadata):
    kind = "metric_alert"
    row = project(kind, SCOPE, native(kind), CONTRACTS[kind][1])
    collections = [{"type": family, "scope": SCOPE, "service": "Microsoft.Insights",
        "status": "collected" if family == kind else "empty",
        "items": [row] if family == kind else []} for family in CONTRACTS]
    snapshot = make_snapshot("azure", [SCOPE], collections, metadata=metadata)
    findings = evaluate_snapshot(snapshot, checks=[ROUTING_ID])["findings"]
    return next(f["status"] for f in findings if f["check_id"] == ROUTING_ID)


def test_genuinely_absent_optional_routing_policy_allows_native_pass():
    assert verdict({}) == "PASS"


@pytest.mark.parametrize("metadata", [
    {"_coverage": {"sw25_policy": {"status": "not_collected"}}},
    {"_coverage": {"compliance_policy": {"status": "denied"}}},
    {"compliance_policy": {"_coverage": {"sw25": {"status": "partial"}}}},
])
def test_declared_unreadable_policy_cannot_default_to_optional_pass(metadata):
    assert verdict(metadata) == "UNKNOWN"


@pytest.mark.parametrize("metadata", [
    {"_coverage": {"sw25_policy": {"status": "collected"}}},
    {"_coverage": {"compliance_policy": {"status": "collected"}}},
    {"compliance_policy": {"_coverage": {"sw25": {"status": "collected"}}}},
    {"_coverage": []},
])
def test_declared_missing_or_malformed_policy_parent_remains_unknown(metadata):
    assert verdict(metadata) == "UNKNOWN"


def test_unrelated_modern_sw25_checks_leave_routing_optional():
    metadata = {"compliance_policy": {"sw25": {"status": "collected", "scope": SCOPE,
        "checks": {"another-control": {"scope": SCOPE}}}}}
    assert verdict(metadata) == "PASS"


def test_existing_legacy_same_cid_requirement_retains_authority():
    metadata = {"sw25_policy": {ROUTING_ID: {"scope": SCOPE}}}
    assert verdict(metadata) == "PASS"
