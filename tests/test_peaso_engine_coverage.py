"""Unknown coverage carries safe evidence-gap reasons in JSON and Markdown."""
from dataclasses import replace
import json
import pytest
from peaso import engine
from peaso.checks import CHECKS
from peaso.snapshot import make_snapshot
from peaso.reports import render_markdown


def report(items, status="collected", **extra):
    snapshot = make_snapshot("aws", ["fixture"], [{"type": "rds_instance", "scope": "fixture", "status": status, "items": items, **extra}])
    return engine.evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.rds.encryption"])


def check_rows(result):
    return [c for c in result["coverage"] if c["level"] == "check"]


def test_missing_field_unknown_reason_matches_json_and_markdown():
    result = report([{"id": "fixture"}])
    reason = check_rows(result)[0]["reason"]
    assert reason == "Missing collected field: StorageEncrypted."
    assert reason in json.dumps(result)
    assert reason in render_markdown(result)


@pytest.mark.parametrize("state", ["unknown", "denied", "malformed", "timeout", "not_collected", "partial"])
def test_unavailable_inventory_unknown_reason_ignores_raw_sdk_payload(state):
    result = report([], state, error={"code": "PRIVATE_TOKEN_SENTINEL", "message": "untrusted SDK message"})
    for row in result["coverage"]:
        if row["status"] in {"unknown", "denied", "malformed", "timeout", "not_collected", "partial"}:
            assert row["reason"]
            assert "PRIVATE_TOKEN_SENTINEL" not in row["reason"]
            assert "SDK message" not in row["reason"]


def test_resource_unknown_empty_reason_gets_explicit_no_conclusive_fallback(monkeypatch):
    native = next(c for c in CHECKS if c.id == "aws.rds.encryption")
    monkeypatch.setattr(engine, "_registry", lambda: [replace(native, evaluate=lambda item, index: ("UNKNOWN", {}))])
    assert check_rows(report([{"id": "fixture"}]))[0]["reason"] == "No conclusive evidence was available for this selected check."


def test_scope_unknown_coverage_explains_missing_dependency(monkeypatch):
    native = next(c for c in CHECKS if c.id == "aws.rds.encryption")
    scoped = replace(native, target="scope", declared_dependencies=("rds_instance", "vpc"))
    monkeypatch.setattr(engine, "_registry", lambda: [scoped])
    result = report([])
    assert "dependency inventory" in check_rows(result)[0]["reason"]


def test_known_collected_inventory_without_resources_has_nonempty_unknown_reason():
    result = report([])
    row = check_rows(result)[0]
    assert row["status"] == "unknown"
    assert row["reason"] == "No conclusive evidence was available for this selected check."


def test_observation_and_applicability_reasons_preserve_gap_without_payloads():
    for reason, word in (("applicability unresolved secret=PRIVATE", "applicability"), ("activity observation window missing PRIVATE", "observation window")):
        safe = engine._unknown_coverage_reason([{"status": "UNKNOWN", "evidence": {"reason": reason}}])
        assert word in safe and "PRIVATE" not in safe
