"""Strict cutoff/null/enabled/root and timezone truth cases for source variants."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

from peaso.checks import CHECKS, aws_a_iam_usage
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_a_iam_usage.NATIVE_IDS}
CONTEXT = {"context": {"created_at": "2026-10-10T12:00:00+00:00"}}


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_usage_source_variants_have_real_states_without_mutation(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("manual", "MANUAL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        before = copy.deepcopy(item)
        assert check.evaluate(item, CONTEXT)[0] == expected
        assert item == before
    assert check.evaluate({"collection_status": "denied"}, CONTEXT)[0] == "UNKNOWN"


@pytest.mark.parametrize("days", [45, 90])
def test_exact_utc_current_date_cutoff_is_strict_less_than_not_age_floor(days):
    check = REGISTRY[f"aws.a.iam.unused_credentials_{days}_days"]
    cutoff = datetime(2026, 10, 10, tzinfo=timezone.utc) - timedelta(days=days)
    item = aws_a_iam_usage.usage_fixture(days)
    item["password_last_used"] = cutoff.isoformat()
    assert check.evaluate(item, CONTEXT)[0] == "PASS"
    item["password_last_used"] = (cutoff - timedelta(seconds=1)).isoformat()
    assert check.evaluate(item, CONTEXT)[0] == "FAIL"


@pytest.mark.parametrize("days", [45, 90])
def test_active_key_null_last_use_falls_back_to_rotation_date_but_disabled_key_is_skipped(days):
    check = REGISTRY[f"aws.a.iam.unused_credentials_{days}_days"]
    item = aws_a_iam_usage.usage_fixture(days)
    item.update({"password_enabled": "false", "access_key_1_active": "true", "access_key_1_last_used_date": "N/A", "access_key_1_last_rotated": "2026-01-01T00:00:00+00:00"})
    assert check.evaluate(item, CONTEXT)[0] == "FAIL"
    item["access_key_1_active"] = "false"
    assert check.evaluate(item, CONTEXT)[0] == "PASS"


def test_45_and_90_days_are_distinct_security_thresholds():
    item = aws_a_iam_usage.usage_fixture(45)
    item["password_last_used"] = "2026-08-11T00:00:00+00:00"
    assert REGISTRY["aws.a.iam.unused_credentials_45_days"].evaluate(item, CONTEXT)[0] == "FAIL"
    assert REGISTRY["aws.a.iam.unused_credentials_90_days"].evaluate(item, CONTEXT)[0] == "PASS"


def test_missing_clock_fields_and_unrecognized_report_values_stay_unknown():
    check = REGISTRY["aws.a.iam.unused_credentials_45_days"]
    item = aws_a_iam_usage.usage_fixture(45)
    assert check.evaluate(item, {})[0] == "UNKNOWN"
    item["password_last_used"] = "not-a-date"
    assert check.evaluate(item, CONTEXT)[0] == "UNKNOWN"
