"""Directed registered storage evidence boundary cases."""
import pytest
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    from tests import test_peaso_compliance_new_sw23 as t

sw = t.sw
fixture = t.fixture
evaluate = t.evaluate
ACCOUNT = t.ACCOUNT
CONTAINER = t.CONTAINER


@pytest.mark.parametrize("case,expected", [
    ("native_region_conflicts", "UNKNOWN"),
    ("native_region_matches", "PASS"),
    ("native_region_casefold", "PASS"),
    ("native_region_malformed", "UNKNOWN"),
    ("classified_location_violation", "FAIL"),
])
def test_storage_geo_native_primary_region_binding(case, expected):
    row, ev = fixture(sw.GEO)
    if case == "native_region_conflicts":
        row["location"] = "eastus"
    elif case == "native_region_matches":
        row["location"] = "westeurope"
    elif case == "native_region_casefold":
        row["location"] = "WestEurope"
    elif case == "native_region_malformed":
        row["location"] = []
    elif case == "classified_location_violation":
        row["location"] = "westeurope"
        ev["customer_data_resources"]["items"][0]["locations"] = ["eastus", "westeurope"]
    assert evaluate(sw.GEO, row, ev) == expected


@pytest.mark.parametrize("case,expected", [
    ("exact_object_binding", "PASS"),
    ("foreign_container_binding", "UNKNOWN"),
    ("foreign_account_binding", "UNKNOWN"),
    ("unresolved_acl", "UNKNOWN"),
])
def test_uniform_object_grant_parent_binding(case, expected):
    row, ev = fixture(sw.UNIFORM)
    obj = ev["containers"]["items"][0]["objects"]["items"][0]
    obj["container_id"] = CONTAINER
    obj["account_id"] = ACCOUNT
    if case == "foreign_container_binding":
        obj["container_id"] = CONTAINER + "-other"
    elif case == "foreign_account_binding":
        obj["account_id"] = ACCOUNT + "-other"
    elif case == "unresolved_acl":
        obj["effective_acl_resolved"] = False
    assert evaluate(sw.UNIFORM, row, ev) == expected


@pytest.mark.parametrize("case,expected", [
    ("stored_policy_overlong", "FAIL"),
    ("issuer_scope_unresolved", "UNKNOWN"),
    ("stored_policy_one_hour", "PASS"),
])
def test_sas_issued_grant_boundary_with_enforcing_account_policy(case, expected):
    row, ev = fixture(sw.SAS)
    token = ev["tokens"]["items"][0]
    token["kind"] = "stored_policy"
    if case == "stored_policy_overlong":
        token["effective_start"] = "2026-10-12T10:59:59+00:00"
    elif case == "issuer_scope_unresolved":
        ev["issuer_inventory_complete"] = False
    assert evaluate(sw.SAS, row, ev) == expected


@pytest.mark.parametrize("case", ["sas", "uniform", "geo"])
def test_affected_existing_storage_contracts(case):
    if case == "sas":
        t.test_sas_enforcement_defaults_actual_issued_interval_and_unresolved_tokens()
    elif case == "uniform":
        t.test_pass_fail(sw.UNIFORM, None)
    else:
        t.test_geo_processing_replicas_policy_and_complete_classification()
