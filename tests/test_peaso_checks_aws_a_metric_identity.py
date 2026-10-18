"""Inert truth counterexamples for the reviewed metric-identity SQL defect."""
import json
from pathlib import Path


def test_same_name_other_namespace_is_a_different_metric_and_not_valid_alarm_coverage():
    filter_metric = {"name": "RootUsage", "namespace": "SecurityAudit", "dimensions": (), "region": "us-east-1", "account": "123456789012"}
    unrelated_alarm = {**filter_metric, "namespace": "Unrelated"}
    # Exact name-only predicate from the inspected SQL join; no upstream SQL
    # or runtime is executed, and no events or real inventory are read.
    assert filter_metric["name"] == unrelated_alarm["name"]
    assert (filter_metric["namespace"], filter_metric["name"], filter_metric["dimensions"]) != (unrelated_alarm["namespace"], unrelated_alarm["name"], unrelated_alarm["dimensions"])


def test_same_name_other_region_or_account_cannot_satisfy_declared_metric_identity():
    expected = ("123456789012", "us-east-1", "SecurityAudit", "RootUsage")
    foreign_region = ("123456789012", "eu-west-1", "SecurityAudit", "RootUsage")
    foreign_account = ("999999999999", "us-east-1", "SecurityAudit", "RootUsage")
    assert expected[-1] == foreign_region[-1] == foreign_account[-1]
    assert expected != foreign_region
    assert expected != foreign_account


def test_metric_defect_reviews_are_exact_retained_source_ids_with_digests_not_fake_ports():
    root = Path(__file__).resolve().parents[1]
    reviewed = json.loads((root / "peaso/rulepacks/reviewed_aws_a_metric_identity.json").read_text())
    rows = {r["check_id"]: r for r in json.loads((root / "peaso/rulepacks/upstream_manifest.json").read_text())["checks"]}
    base = set(json.loads((root / "peaso/rulepacks/port_partitions.json").read_text())["partitions"]["aws_a"]["check_ids"])
    transferred = set(json.loads((root / "peaso/rulepacks/port_partitions_claude.json").read_text())["partitions"]["claude_aws_a"]["check_ids"])
    assert len(reviewed) == 134
    assert len({r["reviewed_query_id"] for r in reviewed.values()}) == 15
    for cid, review in reviewed.items():
        assert cid in base - transferred
        assert review["disposition"] == "rejected"
        assert review["review_classification"] == "invalid_predicate"
        assert review["native_checks"] == []
        assert review["reviewed_source"]["evaluator_sha256"] == rows[cid]["upstream_evaluator"]["sha256"]
        assert review["counterexample"]["source_name_only_match"] is True
        assert review["counterexample"]["same_metric_identity"] is False
        assert review["official_docs"]
