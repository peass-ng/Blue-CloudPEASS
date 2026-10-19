"""Bounded attestation events never imply historical coverage or approved builds."""
import pytest

from peaso.checks.aws_enclave_debug_review_20261019 import evaluate, fixture


@pytest.mark.parametrize("debug,status", [(True, "FAIL"), (False, "PASS")])
def test_observed_measurements(debug, status):
    item, index = fixture(debug)
    assert evaluate(item, index)[0] == status


@pytest.mark.parametrize("field", ["PCR0", "PCR1", "PCR2"])
def test_missing_measurement_is_not_good_evidence(field):
    item, index = fixture(False)
    item["AttestationPcrs"].pop(field)
    assert evaluate(item, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("change", ["foreign_account", "foreign_region", "window", "source", "missing", "malformed"])
def test_unbound_or_missing_events_unknown(change):
    item, index = fixture(False)
    if change == "foreign_account":
        item["AccountId"] = "999999999999"
    elif change == "foreign_region":
        item["Region"] = "eu-west-1"
    elif change == "window":
        item["EventTime"] = "2026-10-19T12:00:00Z"
    elif change == "source":
        item["_provenance"]["source_operation"] = "external"
    elif change == "missing":
        item = {}
    else:
        item["AttestationPcrs"]["PCR0"] = "malformed"
    assert evaluate(item, index)[0] == "UNKNOWN"
