"""Benign source counterexamples preserve exclusions without false support."""
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path

import pytest

PACK = Path(__file__).resolve().parents[1] / "peaso" / "rulepacks"
AUDIT = json.loads((PACK / "lead_audit_counterexamples.json").read_text())


@pytest.mark.parametrize("case", AUDIT["iam_server_certificate_not_expired"]["counterexamples"])
def test_date_cutoff_misses_certificates_already_expired_at_capture(case):
    captured = datetime.fromisoformat(case["captured_at"])
    expiration = datetime.fromisoformat(case["expiration"])
    source_cutoff = captured.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(seconds=1)
    assert expiration >= source_cutoff  # Literal source would emit ok.
    assert expiration < captured  # Timestamp requirement already violated.
    assert case["source_status"] == "PASS" and case["requirement_status"] == "FAIL"


def test_support_where_removes_account_and_policy_name_is_not_policy_identity():
    absent, impostor = AUDIT["iam_support_role"]["counterexamples"]
    survivors = [arn for arn in absent["attached_policy_arns"] if arn.split("/")[1] == "AWSSupportAccess"]
    grouped_accounts = {absent["account_id"]: len(survivors)} if survivors else {}
    assert grouped_accounts == {} and absent["source_status"] == "NO_RESULT"
    customer_arn = impostor["attached_policy_arns"][0]
    assert customer_arn.split("/")[1] == "AWSSupportAccess"
    assert customer_arn != "arn:aws:iam::aws:policy/AWSSupportAccess"
    assert impostor["customer_policy_support_permissions"] is False


VERIFIED = {key: entry for key, entry in json.loads((PACK / "reviewed_aws_gap.json").read_text()).items() if "verification" in entry}


def _lead_native_inputs(query, case):
    """Native inputs that encode one inert lead counterexample (no cloud data)."""
    from peaso.checks.claude_aws_a_common import ACCOUNT, idx
    from peaso.checks.claude_aws_a_iam import attach
    if query == "iam_support_role":
        return {}, idx(iam_role=[attach("iam_role", arn) for arn in case["attached_policy_arns"]])
    index = idx()
    index["context"]["created_at"] = case["captured_at"]
    return {"ServerCertificateName": "c", "Arn": "arn:aws:iam::%s:server-certificate/c" % ACCOUNT, "Expiration": case["expiration"]}, index


def _native_status(native, query, case):
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == native)
    item, index = _lead_native_inputs(query, case)
    return check.evaluate(item, index)[0]


@pytest.mark.parametrize("query,expected_count", [("iam_support_role", 10), ("iam_server_certificate_not_expired", 9)])
def test_each_independently_reviewed_control_retains_source_and_framework_metadata(query, expected_count):
    """Lead-reviewed rows stay rejected unless a merge carries a recorded, reproducible verification."""
    manifest = json.loads((PACK / "upstream_manifest.json").read_text())
    evidence = AUDIT[query]
    rows = [row for row in manifest["checks"] if row["check_id"] in evidence["source_check_ids"]]
    assert len(rows) == expected_count
    for row in rows:
        verification = VERIFIED.get(row["check_id"], {}).get("verification")
        if verification is None:
            assert row["disposition"] == "rejected"
            assert row["review_classification"] == "invalid_predicate"
            assert row["native_checks"] == [] and row["native_evaluators"] == []
        else:
            native = verification["native"]
            assert row["disposition"] == "merged" and row["native_checks"] == [native]
            assert verification["evaluator_sha256"] == evidence["evaluator_sha256"]
            assert verification["framework_mapping_sha256"] == evidence["framework_mapping_sha256"][row["check_id"]]
            assert verification["requirement"] and verification["counterexamples_source"].endswith("#" + query)
            recorded = verification["counterexample_results"]
            assert [{k: v for k, v in case.items() if k != "native_status"} for case in recorded] == evidence["counterexamples"]
            for case in recorded:
                # The recorded result must still be reproduced by the native, and must equal the requirement (not the source) status.
                assert case["native_status"] == case["requirement_status"] == _native_status(native, query, case)
        assert row["revision"] == evidence["revision"]
        assert row["upstream_evaluator"]["sha256"] == evidence["evaluator_sha256"]
        assert row["upstream_evaluator"]["query_ids"] == [query]
        mapping_digest = hashlib.sha256(json.dumps(row["frameworks"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        assert mapping_digest == evidence["framework_mapping_sha256"][row["check_id"]]
        assert all(mapping["framework_id"] and mapping["control_id"] and mapping["version"] for mapping in row["frameworks"])


def test_merges_of_lead_reviewed_rows_require_recorded_verification():
    """No shard may support a lead-reviewed source id without the verification record."""
    lead_ids = {cid for query in ("iam_support_role", "iam_server_certificate_not_expired") for cid in AUDIT[query]["source_check_ids"]}
    manifest = {row["check_id"]: row for row in json.loads((PACK / "upstream_manifest.json").read_text())["checks"]}
    for cid in lead_ids:
        if manifest[cid]["disposition"] in ("ported", "merged"):
            assert cid in VERIFIED, cid


def test_generated_coverage_summary_is_the_same_accepted_source_snapshot():
    summary = json.loads((PACK / "catalog_summary.json").read_text())
    runtime = json.loads((PACK / "runtime_metadata.json").read_text())
    assert {key: value for key, value in summary.items() if key not in ("phase", "inventory_coverage", "active_native_checks", "automation_scope")} == runtime["coverage"]
    from peaso.checks import CHECKS
    from peaso.checks.native_only import automated_checks, scope
    assert summary["active_native_checks"] == len(automated_checks(CHECKS))
    assert summary["automation_scope"] == scope()
    from peaso.collectors.bulk_evidence import coverage
    assert summary["inventory_coverage"] == coverage()
    assert sum(summary["upstream"].values()) == summary["upstream_total"]
    assert summary["supported_upstream"] == summary["upstream"]["ported"] + summary["upstream"]["merged"]
    pending_facts = any(row["unavailable_projections"] for row in summary["inventory_coverage"].values())
    expected_phase = "expansion_in_progress" if summary["upstream"]["pending"] or pending_facts else "review_complete"
    assert summary["phase"] == expected_phase
