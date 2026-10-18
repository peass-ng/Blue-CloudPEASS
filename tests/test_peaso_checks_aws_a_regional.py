"""Differential regional absence/status truth cases from pinned predicates."""
import copy
import json
from pathlib import Path

import pytest

from peaso.checks import CHECKS, aws_a_regional
from peaso.checks.aws_a_facts import scope_fixture
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS if c.id in aws_a_regional.NATIVE_IDS}
SUBJECT = aws_a_regional.SUBJECT


@pytest.mark.parametrize("cid", sorted(REGISTRY))
def test_regional_presence_pass_fail_missing_denied_malformed_and_purity(cid):
    check, cases = REGISTRY[cid], CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state])
        index = copy.deepcopy(cases.get(state + "_index", cases["index"]))
        before = copy.deepcopy((item, index))
        assert check.evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert check.evaluate({"collection_status": "denied"}, cases["index"])[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", sorted(REGISTRY))
@pytest.mark.parametrize("state", ["denied", "partial", "malformed", "unknown", "timeout", "not_collected"])
def test_empty_is_security_failure_only_after_successful_complete_collection(cid, state):
    check = REGISTRY[cid]
    assert check.evaluate(SUBJECT, scope_fixture(check.kind, [], status=state))[0] == "UNKNOWN"
    assert check.evaluate(SUBJECT, scope_fixture(check.kind, []))[0] == "FAIL"


@pytest.mark.parametrize("status,expected", [("ENABLED", "PASS"), ("DISABLED", "FAIL"), ("unknown", "UNKNOWN")])
def test_detector_config_status_and_denied_detail_are_not_inferred(status, expected):
    check = REGISTRY["aws.a.guardduty.region_enabled"]
    assert check.evaluate(SUBJECT, scope_fixture("guardduty_detector", [{"Configuration": {"Status": status}}]))[0] == expected
    assert check.evaluate(SUBJECT, scope_fixture("guardduty_detector", [{"Configuration": {"Status": status, "collection_status": "denied"}}]))[0] == "UNKNOWN"


@pytest.mark.parametrize("recording,last_status,expected", [(True, "Success", "PASS"), (True, "Pending", "PASS"), (True, "Failure", "FAIL"), (False, "Success", "FAIL"), (True, "SUCCESS", "UNKNOWN")])
def test_config_preserves_native_case_and_pinned_nonfailure_predicate(recording, last_status, expected):
    row = {"name": "default", "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": recording, "lastStatus": last_status}]}}
    assert REGISTRY["aws.a.config.region_recorder_enabled"].evaluate(SUBJECT, scope_fixture("config_recorder", [row]))[0] == expected


def test_foreign_or_missing_recorder_status_cannot_satisfy_region():
    row = {"name": "default", "Status": {"ConfigurationRecordersStatus": [{"name": "foreign", "recording": True, "lastStatus": "Success"}]}}
    assert REGISTRY["aws.a.config.region_recorder_enabled"].evaluate(SUBJECT, scope_fixture("config_recorder", [row]))[0] == "UNKNOWN"


def test_pinned_config_case_defect_has_real_native_counterexamples():
    # Independent literal truth cases from the reviewed SQL condition. Do not
    # execute the upstream SQL or import its runtime.
    assert ("Failure" == "FAILURE") is False
    assert ("Success" == "SUCCESS") is False
    failure = {"name": "default", "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": "Failure"}]}}
    healthy = {"name": "default", "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": "Success"}]}}
    check = REGISTRY["aws.a.config.region_recorder_enabled"]
    assert check.evaluate(SUBJECT, scope_fixture("config_recorder", [failure]))[0] == "FAIL"
    assert check.evaluate(SUBJECT, scope_fixture("config_recorder", [healthy]))[0] == "PASS"


def test_rejected_regions_use_current_official_evidence_and_do_not_claim_fake_ports():
    root = Path(__file__).resolve().parents[1]
    rows = json.loads((root / "peaso/rulepacks/reviewed_aws_a_regional.json").read_text())
    for row in rows.values():
        assert row["reason"]
        assert row["official_docs"]
        assert row["reviewed_source"]["revision"]
        if row["disposition"] == "rejected":
            assert row["native_checks"] == []
            assert row["review_classification"] == "invalid_predicate"
    assert sum(r["disposition"] == "ported" for r in rows.values()) == 2
    assert sum(r["disposition"] == "rejected" for r in rows.values()) == 21
