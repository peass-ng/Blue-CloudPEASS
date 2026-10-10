"""Counterexamples substantiate invalid/obsolete automation; no fake native ports."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REVIEWS = json.loads((ROOT / "peaso/rulepacks/reviewed_azure_ports_invalid.json").read_text())


def test_boolean_count_predicate_counts_false_values_and_cannot_measure_disabled_settings():
    duckdb = pytest.importorskip("duckdb")
    with duckdb.connect(":memory:") as db:
        source, actual = db.execute("SELECT count(value = 'Disabled'), count(*) FILTER (WHERE value = 'Disabled') FROM (SELECT 'Audit' AS value)").fetchone()
    assert source == 1 and actual == 0
    cases = [row for row in REVIEWS.values() if row["source_review"]["query_id"] == "securitycenter_asc_default_setting_not_disabled"]
    assert cases and all(row["source_review"]["counterexample"]["source_status"] == "alarm" for row in cases)


def test_guest_creation_date_has_no_equivalence_to_actual_review_date():
    duckdb = pytest.importorskip("duckdb")
    with duckdb.connect(":memory:") as db:
        source = db.execute("SELECT CASE WHEN NOT account_enabled THEN 'alarm' WHEN created <= (captured_clock - INTERVAL '30' DAY) THEN 'alarm' ELSE 'ok' END FROM (SELECT TRUE AS account_enabled, TIMESTAMP '2020-01-01' AS created, TIMESTAMP '2026-10-10' AS captured_clock)").fetchone()[0]
    assert source == "alarm"
    examples = [row["source_review"]["counterexample"] for row in REVIEWS.values() if row["source_review"]["query_id"] == "ad_guest_user_reviewed_monthly"]
    assert examples and all(example["actual_reviewedDateTime"].startswith("2026-10-09") for example in examples)


def test_rejections_are_exclusive_substantive_and_not_missing_fact_shortcuts():
    claude = set(json.loads((ROOT / "peaso/rulepacks/port_partitions_claude.json").read_text())["partitions"]["claude_azure"]["check_ids"])
    assert not set(REVIEWS) & claude
    assert {review["review_classification"] for review in REVIEWS.values()} == {"invalid_predicate", "obsolete_definition"}
    for review in REVIEWS.values():
        assert review["disposition"] == "rejected" and review["native_checks"] == []
        assert review["official_docs"] and review["source_review"]["counterexample"]
        assert review["source_review"]["arguments"] == []
        assert review["source_review"]["counterexample"]["source_status"] in ("alarm", "ok")
        assert review["source_review"]["counterexample"]["requirement_truth"]
