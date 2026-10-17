"""Known-empty regional inventories fail required presence; gaps do not."""
from peaso.checks import CHECKS, aws_b_regional
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
import pytest


@pytest.mark.parametrize("kind", ["backup_plan", "backup_vault"])
@pytest.mark.parametrize("status,expected", [("empty", "FAIL"), ("collected", "PASS"), ("partial", "UNKNOWN"), ("denied", "DENIED"), ("not_collected", "UNKNOWN")])
def test_required_regional_presence(kind, status, expected):
    scope = "111111111111/us-east-1"
    items = [{"id": "configured"}] if status in ("collected", "partial") else []
    snapshot = make_snapshot("aws", [scope], [{"type": kind, "scope": scope, "status": status, "items": items}])
    report = evaluate_snapshot(snapshot, categories=["hardening"], checks=["aws.b." + kind + ".regional_presence"])
    assert report["findings"][0]["status"] == expected


def test_backup_report_applicability_and_missing_join():
    check = next(c for c in CHECKS if c.id == "aws.b.backup.report_plan_presence")
    item = {"scope": "111111111111/us-east-1"}
    empty = {"collections": {"backup_plan": [{"status": "empty"}], "backup_report_plan": [{"status": "empty"}]}, "backup_plan": [], "backup_report_plan": []}
    assert check.evaluate(item, empty)[0] == "MANUAL"
    empty["backup_plan"] = [{"data": {"id": "configured"}}]
    empty["collections"]["backup_plan"][0]["status"] = "collected"
    assert check.evaluate(item, empty)[0] == "FAIL"
    empty["collections"]["backup_report_plan"][0]["status"] = "partial"
    assert check.evaluate(item, empty)[0] == "UNKNOWN"


def test_inspector_organization_auto_enable_is_not_account_activation():
    check = next(c for c in CHECKS if c.id == "aws.b.inspector.lambda_organization_auto_enable")
    item = {"scope": "111111111111/us-east-1"}
    idx = {"collections": {"inspector_organization_configuration": [{"status": "collected"}]}, "inspector_organization_configuration": [{"data": {"autoEnable": {"lambda": True}}}]}
    status, evidence = check.evaluate(item, idx)
    assert status == "PASS" and "not a claim" in evidence["semantics"]
    assert check.evaluate(item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("code, expected", [("not_delegated_administrator", "NOT_APPLICABLE"), ("region_operation_unsupported", "NOT_APPLICABLE"), (None, "FAIL")])
def test_inspector_organization_auto_enable_not_delegated_admin_is_na(code, expected):
    check = next(c for c in CHECKS if c.id == "aws.b.inspector.ec2_organization_auto_enable")
    index = {"collections": {"inspector_organization_configuration": [{"status": "empty", "items": [], **({"error": {"code": code}} if code else {})}]}, "inspector_organization_configuration": []}
    assert check.evaluate({"scope": "111111111111/us-east-1"}, index)[0] == expected
