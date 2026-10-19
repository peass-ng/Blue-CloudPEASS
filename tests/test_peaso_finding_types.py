"""Primary finding purposes are complete, explicit and independent of scan categories."""
import pytest
from peaso.analysis import ANALYSIS_CHECKS
from peaso.checks import CHECKS
from peaso.finding_types import type_for, registry, validate_review


def test_every_registered_check_has_exactly_one_reviewed_type():
    ids = [c.id for c in CHECKS] + [c["id"] for c in ANALYSIS_CHECKS]
    validate_review(ids)
    assert all(type_for(cid) != "unclassified" for cid in ids)
    with pytest.raises(ValueError, match="missing="):
        validate_review(ids + ["aws.new.check"])
    assert type_for("historical.unknown") == "unclassified"
    assert type_for("historical.technique", "privesc") == "permissions"


@pytest.mark.parametrize("cid,expected", [
    ("aws.ebs.encryption", "encryption"), ("aws.s3.versioning", "backups"),
    ("aws.a.cloudwatch.finite_retention_365", "logging"),
    ("aws.a.cloudwatch.alarm_actions_enabled", "monitoring"),
    ("aws.claude_a.iam.custom_policy_no_cloudtrail_star", "permissions"),
    ("aws.iam.root_mfa", "authentication"), ("aws.cloudtrail.kms_encryption", "encryption"),
    ("gcp.sql.backups", "backups"), ("gcp.reviewed.storage.lifecycle", "asset_lifecycle"),
    ("azure.storage.blob_versioning", "backups"), ("azure.other.storage_geo", "data_privacy"),
    ("k8s.ports.deployment.cpu_limit", "workload_hardening"),
    ("k8s.ports.deployment.cpu_request", "availability"),
    ("analysis.coverage", "inventory_coverage"), ("analysis.inactive_identity", "asset_lifecycle"),
])
def test_reviewed_examples_span_purposes_and_providers(cid, expected):
    assert type_for(cid) == expected


def test_types_are_exposed_in_the_catalog_and_native_findings():
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    from peaso.snapshot import make_snapshot
    check = next(c for c in CHECKS if c.id == "aws.ebs.encryption")
    assert check.public()["finding_type"] == "encryption"
    report = evaluate_snapshot(make_snapshot("aws", ["test"], []), checks=[check.id])
    assert all(row["finding_type"] == "encryption" for row in hydrate_frameworks(report)["findings"])
