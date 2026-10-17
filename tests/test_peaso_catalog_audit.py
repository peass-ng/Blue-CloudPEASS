"""Consistency gate catches unsupported coverage claims and lost controls."""
import copy
import gzip
import json

import pytest

from scripts.peaso_catalog_audit import FILES, audit_directory, audit_documents, main
from scripts.peaso_compliance_compile import lookup_index


@pytest.fixture
def catalogs():
    native = {"id": "aws.storage.encryption", "provider": "aws", "frameworks": ["HackTricks Cloud Best Practices"],
              "framework_ids": ["cis.test"], "dependencies": ["bucket"], "expected_cost": {"cloud_calls": 0},
              "mapping": {"CIS": {"controls": [{"framework_id": "cis.test", "control_id": "2.1", "version": "1.0"}]}}}
    supported = {"check_id": "source.encryption", "provider": "aws", "disposition": "ported",
                 "native_checks": [native["id"]], "reason": "Reviewed pinned predicate and collection inputs.",
                 "expected_cost": {"cloud_calls_at_evaluation": 0}, "service": "s3",
                 "frameworks": [{"framework_id": "cis.test", "control_id": "2.1", "version": "1.0"}]}
    summary = {"native_checks": 1, "upstream_total": 1, "upstream": {"ported": 1}, "supported_upstream": 1,
               "manual_requirements": 0, "rejected_invalid_predicates": 0, "outside_runtime_provider_scope": 0,
               "runtime_scope_upstream_total": 1}
    return {"upstream_manifest.json": {"checks": [supported]}, "native_catalog.json": {"checks": [native]},
            "runtime_metadata.json": {"coverage": copy.deepcopy(summary)}, "catalog_summary.json": summary,
            "framework_catalog.json": {"frameworks": [{"id": "cis.test", "provider": "aws", "source_checks": 1,
                "pending_source_checks": 0, "supported_native_checks": 1}]},
            "manual_catalog.json": {"requirements": []}}


def codes(result):
    return {issue["code"] for issue in result["issues"]}


def test_complete_consistent_catalog_does_not_claim_certification(catalogs):
    report = audit_documents(catalogs)
    assert report["catalog_consistent"] and report["coverage_complete"]
    assert report["providers"]["aws"]["native_predicates"] == 1
    assert report["frameworks"][0]["control_version_pairs"] == 1
    assert "zero false positives" in report["limitations"][-1]


def test_explicit_zero_dispositions_are_not_stale_counts(catalogs):
    for name in ("catalog_summary.json", "runtime_metadata.json"):
        summary = catalogs[name] if name == "catalog_summary.json" else catalogs[name]["coverage"]
        summary["upstream"].update(pending=0, rejected=0, merged=0, out_of_scope=0)
    report = audit_documents(catalogs)
    assert report["catalog_consistent"] and report["coverage_complete"]


def test_unsupported_native_mapping_cannot_count_as_implemented(catalogs):
    catalogs["upstream_manifest.json"]["checks"][0]["native_checks"] = ["aws.missing"]
    assert "missing_native_predicate" in codes(audit_documents(catalogs))


def test_cross_provider_predicate_is_not_an_equivalent_mapping(catalogs):
    catalogs["native_catalog.json"]["checks"][0]["provider"] = "gcp"
    assert "provider_mismatch" in codes(audit_documents(catalogs))


def test_lost_control_mapping_and_stale_summary_are_detected(catalogs):
    catalogs["native_catalog.json"]["checks"][0]["framework_ids"] = []
    catalogs["catalog_summary.json"]["supported_upstream"] = 999
    assert {"lost_framework_mapping", "stale_summary"} <= codes(audit_documents(catalogs))


def test_framework_id_alone_cannot_hide_a_lost_control_version(catalogs):
    catalogs["native_catalog.json"]["checks"][0]["mapping"]["CIS"]["controls"][0]["version"] = "0.9"
    report = audit_documents(catalogs)
    assert "lost_control_mapping" in codes(report)
    assert "lost_framework_mapping" not in codes(report)


def test_pending_reference_does_not_inherit_supported_coverage(catalogs):
    row = catalogs["upstream_manifest.json"]["checks"][0]
    row.update(disposition="pending", native_checks=[])
    report = audit_documents(catalogs)
    assert not report["coverage_complete"]
    assert report["counts"]["supported_upstream"] == 0
    assert report["providers"]["aws"]["pending_services"] == {"s3": 1}


def test_two_controls_reusing_one_predicate_keep_distinct_mappings(catalogs):
    row = copy.deepcopy(catalogs["upstream_manifest.json"]["checks"][0])
    row.update(check_id="source.encryption.other", disposition="merged")
    row["frameworks"][0]["control_id"] = "2.2"
    catalogs["upstream_manifest.json"]["checks"].append(row)
    report = audit_documents(catalogs)
    assert report["frameworks"][0]["control_version_pairs"] == 2
    assert report["frameworks"][0]["native_predicates"] == 1
    assert report["counts"]["supported_upstream"] == 2


def test_manual_control_is_not_an_automated_predicate(catalogs):
    row = catalogs["upstream_manifest.json"]["checks"][0]
    row.update(disposition="rejected", native_checks=[], manual_requirement={"question": "Review ownership"})
    report = audit_documents(catalogs)
    assert report["counts"]["manual_requirements"] == 1
    assert report["counts"]["rejected_invalid_predicates"] == 0
    assert "manual_catalog_mismatch" in codes(report)


def test_duplicate_identifiers_cannot_inflate_native_coverage(catalogs):
    catalogs["native_catalog.json"]["checks"].append(copy.deepcopy(catalogs["native_catalog.json"]["checks"][0]))
    report = audit_documents(catalogs)
    assert "duplicate_id" in codes(report)
    assert report["counts"]["native_checks"] == 1


def reviewed_catalogs(catalogs):
    """Upstream source control and signed requirement have distinct IDs."""
    signed = "a" * 64
    cid = "aws.storage.encryption"
    source = catalogs["upstream_manifest.json"]["checks"][0]
    tag = {"framework_id": "cis.test", "requirement_id": "R-1", "decision": "MAPPED",
           "runtime_status": "automated"}
    native = catalogs["native_catalog.json"]
    native["compliance_source_manifest_sha256"] = signed
    native["checks"][0]["requirement_controls"] = [tag]
    native["checks"][0]["mapping"] = {"CIS": {"controls": [{"framework_id": "cis.test", "control_id": "R-1"}]}}
    runtime = catalogs["runtime_metadata.json"]
    runtime["compliance"] = {"source_manifest_sha256": signed, "schema_version": 1}
    runtime["mappings"] = {cid: [copy.deepcopy(source)]}
    frameworks = catalogs["framework_catalog.json"]
    frameworks["compliance_source_manifest_sha256"] = signed
    frameworks["frameworks"][0].update(source_supported_native_checks=1, native_check_ids=[cid],
                                        requirements_total=1, pending_automatable_requirements=0,
                                        requirements_by_status={"automated": 1})
    catalogs["compliance_requirements.json"] = {"schema_version": 1, "source_manifest_sha256": signed,
        "frameworks": [{"id": "cis.test", "name": "CIS test", "provider": "aws", "requirements_total": 1,
                        "requirements": [{"requirement_id": "R-1", "native_checks": [cid],
                                          "pending_checks": [], "runtime_status": "automated"}]}],
        "by_check": {cid: [tag]}, "proposed_checks": [], "counts": {"automated": 1},
        "hacktricks_best_practices": {"requirements_total": None, "reason": "Thematic fixture only."}}
    catalogs["check_descriptions.json"] = {"source_manifest_sha256": signed,
                                          "checks": {cid: {"description": "Reviewed condition."}}}
    refresh_reviewed_lookup(catalogs)
    return catalogs


def refresh_reviewed_lookup(catalogs):
    catalogs["compliance_lookup.json"] = lookup_index(catalogs["compliance_requirements.json"], "b" * 64)


def test_signed_requirements_and_source_references_are_checked_separately(catalogs):
    reviewed_catalogs(catalogs)
    assert audit_documents(catalogs)["catalog_consistent"]
    catalogs["runtime_metadata.json"]["mappings"] = {}
    assert "lost_source_reference" in codes(audit_documents(catalogs))


def test_ported_sources_do_not_hide_pending_automatable_requirements(catalogs):
    reviewed_catalogs(catalogs)
    version = catalogs["compliance_requirements.json"]["frameworks"][0]
    version["requirements"].append({"requirement_id": "R-2", "native_checks": [],
                                    "pending_checks": ["aws.proposed"], "runtime_status": "not_assessed"})
    version["requirements_total"] = 2
    catalogs["framework_catalog.json"]["frameworks"][0].update(
        requirements_total=2, pending_automatable_requirements=1,
        requirements_by_status={"automated": 1, "not_assessed": 1})
    refresh_reviewed_lookup(catalogs)
    report = audit_documents(catalogs)
    assert report["source_reference_coverage_complete"]
    assert report["pending_automatable_requirements"] == 1
    assert not report["coverage_complete"]


def test_zero_pending_with_partial_requirement_is_not_complete(catalogs):
    reviewed_catalogs(catalogs)
    cid = "aws.storage.encryption"
    version = catalogs["compliance_requirements.json"]["frameworks"][0]
    version["requirements"][0]["runtime_status"] = "partial"
    catalogs["compliance_requirements.json"]["counts"] = {"partial": 1}
    catalogs["compliance_requirements.json"]["by_check"][cid][0]["runtime_status"] = "partial"
    catalogs["native_catalog.json"]["checks"][0]["requirement_controls"][0]["runtime_status"] = "partial"
    catalogs["framework_catalog.json"]["frameworks"][0]["requirements_by_status"] = {"partial": 1}
    refresh_reviewed_lookup(catalogs)
    report = audit_documents(catalogs)
    assert report["catalog_consistent"] and report["issues"] == []
    assert report["pending_automatable_requirements"] == 0
    assert report["automation_implementation_complete"]
    assert report["source_reference_coverage_complete"]
    assert not report["coverage_complete"]
    assert report["frameworks"][0]["source_reference_coverage_complete"]
    assert not report["frameworks"][0]["coverage_complete"]


@pytest.mark.parametrize("mutation,expected", [
    ("tag", "stale_reviewed_check_tags"),
    ("control", "lost_reviewed_control_mapping"),
    ("framework", "stale_reviewed_framework_checks"),
    ("hash", "compliance_pack_hash_mismatch"),
    ("description", "missing_reviewed_native_descriptions"),
    ("lookup", "stale_or_missing_compliance_lookup"),
])
def test_reviewed_requirement_materialization_tampering_fails(catalogs, mutation, expected):
    reviewed_catalogs(catalogs)
    cid = "aws.storage.encryption"
    if mutation == "tag":
        catalogs["native_catalog.json"]["checks"][0]["requirement_controls"] = []
    elif mutation == "control":
        catalogs["native_catalog.json"]["checks"][0]["mapping"] = {}
    elif mutation == "framework":
        catalogs["framework_catalog.json"]["frameworks"][0]["native_check_ids"] = []
    elif mutation == "hash":
        catalogs["runtime_metadata.json"]["compliance"]["source_manifest_sha256"] = "b" * 64
    elif mutation == "lookup":
        catalogs["compliance_lookup.json"]["frameworks"][0]["requirements_by_status"] = {"automated": 999}
    else:
        catalogs["check_descriptions.json"]["checks"].pop(cid)
    assert expected in codes(audit_documents(catalogs))


def write_catalogs(tmp_path, catalogs):
    for name in FILES:
        (tmp_path / name).write_text(json.dumps(catalogs[name]))
    raw = (tmp_path / "upstream_manifest.json").read_bytes()
    (tmp_path / "upstream_manifest.json.gz").write_bytes(gzip.compress(raw, mtime=0))


def test_compressed_archive_must_match_json_and_cli_enforces_gate(tmp_path, catalogs, capsys):
    write_catalogs(tmp_path, catalogs)
    assert main(["--rulepacks", str(tmp_path), "--require-complete"]) == 0
    assert json.loads(capsys.readouterr().out)["capture_stable"]
    (tmp_path / "upstream_manifest.json.gz").write_bytes(gzip.compress(b'{}', mtime=0))
    assert main(["--rulepacks", str(tmp_path)]) == 1
    assert "compressed_manifest_mismatch" in codes(json.loads(capsys.readouterr().out))


def test_consistent_partial_catalog_still_fails_complete_coverage_gate(tmp_path, catalogs, capsys):
    catalogs["upstream_manifest.json"]["checks"][0].update(disposition="pending", native_checks=[])
    native = catalogs["native_catalog.json"]["checks"][0]
    native.update(framework_ids=[], mapping={})
    summary = catalogs["catalog_summary.json"]
    summary.update(upstream={"pending": 1}, supported_upstream=0)
    catalogs["runtime_metadata.json"]["coverage"] = copy.deepcopy(summary)
    catalogs["framework_catalog.json"]["frameworks"][0].update(pending_source_checks=1, supported_native_checks=0)
    write_catalogs(tmp_path, catalogs)
    assert main(["--rulepacks", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["catalog_consistent"]
    assert main(["--rulepacks", str(tmp_path), "--require-complete"]) == 1
    assert not json.loads(capsys.readouterr().out)["coverage_complete"]


def test_concurrent_edits_invalidate_capture(tmp_path, catalogs, monkeypatch):
    write_catalogs(tmp_path, catalogs)
    from pathlib import Path
    original = Path.read_bytes
    reads = 0

    def changed(path):
        nonlocal reads
        data = original(path)
        if path.name == "native_catalog.json":
            reads += 1
            if reads == 2:
                return data + b" "
        return data

    monkeypatch.setattr(Path, "read_bytes", changed)
    report = audit_directory(tmp_path)
    assert not report["capture_stable"] and not report["catalog_consistent"]
    assert "concurrent_catalog_edit" in codes(report)
