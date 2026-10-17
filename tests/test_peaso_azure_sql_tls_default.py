"""Offline Azure SQL minimum TLS default and historical observation fixtures."""

import copy

import pytest

from peaso.checks import CHECKS


CHECK = next(check for check in CHECKS if check.id == "azure.claude.sql_server_minimal_tls_12")


def server(value, **extra):
    return {"properties": {"minimalTlsVersion": value}, **extra}


def evaluate(item, observed=None):
    index = {"context": {"created_at": observed}} if observed is not None else {}
    before = copy.deepcopy((item, index))
    result = CHECK.evaluate(item, index)
    assert (item, index) == before
    return result


@pytest.mark.parametrize("value", ["1.2", "1.3"])
def test_explicit_supported_minimum_passes_without_date(value):
    status, evidence = evaluate(server(value))
    assert status == "PASS" and evidence["configured_minimal_tls_version"] == value


@pytest.mark.parametrize("value", ["1.0", "1.1"])
def test_explicit_stale_minimum_fails_as_configuration_only(value):
    status, evidence = evaluate(server(value), "2026-10-13T00:00:00Z")
    assert status == "FAIL" and "not proof" in evidence["semantics"]


def test_observed_current_none_is_effective_provider_default_not_explicit_setting():
    status, evidence = evaluate(server("None"), "2026-10-13T12:00:00Z")
    assert status == "PASS"
    assert evidence["effective_provider_minimum"] == "TLS 1.2"
    assert evidence["explicit_minimum_declared"] is False
    assert evidence["configured_minimal_tls_version"] == "None"


@pytest.mark.parametrize("observed", [
    "2025-08-30T12:00:00Z",  # Before the announced retirement.
    "2026-10-11T23:59:59Z",  # Historical snapshot before the reviewed guarantee.
    "2027-10-13T00:00:00Z",  # Re-review due after the bounded evidence window.
    "not-a-date",
    "2026-10-13T00:00:00",   # Timezone missing.
])
def test_none_without_reviewed_capture_assurance_is_unknown(observed):
    assert evaluate(server("None"), observed)[0] == "UNKNOWN"


def test_item_capture_takes_precedence_over_newer_snapshot_context():
    item = server("None", _provenance={"collected_at": "2025-08-30T12:00:00Z"})
    assert evaluate(item, "2026-10-13T00:00:00Z")[0] == "UNKNOWN"
    item["_provenance"]["collected_at"] = "2026-10-13T00:00:00+02:00"
    assert evaluate(item, "2025-08-30T00:00:00Z")[0] == "PASS"


def test_absent_null_denied_or_malformed_fact_is_not_inferred_as_default():
    for item in ({}, {"properties": {}}, server(None), server(0), server("future"),
                 {**server("None"), "collection_status": "denied"}):
        assert evaluate(item, "2026-10-13T00:00:00Z")[0] == "UNKNOWN"
    assert evaluate(server("None"))[0] == "UNKNOWN"


def test_check_id_kind_and_dependency_unchanged():
    assert CHECK.kind == "sql_server"
    assert CHECK.declared_dependencies == ("sql_server",)
