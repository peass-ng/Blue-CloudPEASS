"""Region identifier casing in the signed SW23 customer-data check."""
import pytest
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    from tests import test_peaso_compliance_new_sw23 as t


@pytest.mark.parametrize("approved,locations,expected", [
    (["westeurope", "northeurope"], ["westeurope", "northeurope"], "PASS"),
    (["WestEurope", "NorthEurope"], ["westeurope", "northeurope"], "PASS"),
    (["westeurope", "northeurope"], ["WestEurope", "NorthEurope"], "PASS"),
    (["WESTEUROPE", "NORTHEUROPE"], ["WestEurope", "NorthEurope"], "PASS"),
    (["westeurope", "northeurope"], ["eastus", "westeurope"], "FAIL"),
    (["westeurope", "northeurope"], ["West Europe", "North Europe"], "FAIL"),
    (["West Europe", "North Europe"], ["westeurope", "northeurope"], "FAIL"),
])
def test_region_identifier_case_and_display_label_boundary(approved, locations, expected):
    row, ev = t.fixture(t.sw.GEO)
    ev["approved_eu_regions"] = approved
    ev["customer_data_resources"]["items"][0]["locations"] = locations
    assert t.evaluate(t.sw.GEO, row, ev) == expected


@pytest.mark.parametrize("case,expected", [
    ("native_primary_matches_case", "PASS"),
    ("native_primary_omitted", "UNKNOWN"),
    ("foreign_resource", "UNKNOWN"),
    ("incomplete_inventory", "UNKNOWN"),
    ("incomplete_locations", "UNKNOWN"),
    ("restriction_unassigned", "FAIL"),
    ("restriction_noncompliant", "FAIL"),
])
def test_case_normalization_retains_evidence_and_policy_guards(case, expected):
    row, ev = t.fixture(t.sw.GEO)
    row["location"] = "westeurope"
    ev["approved_eu_regions"] = ["WestEurope", "NorthEurope"]
    resources = ev["customer_data_resources"]["items"]
    resources[0]["locations"] = ["WestEurope", "NorthEurope"]
    if case == "native_primary_omitted":
        resources[0]["locations"] = ["NorthEurope"]
    elif case == "foreign_resource":
        resources[1]["id"] = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.ApiManagement/service/gateway"
    elif case == "incomplete_inventory":
        ev["classified_inventory_complete"] = False
    elif case == "incomplete_locations":
        resources[0]["primary_replica_processing_locations_complete"] = False
    elif case == "restriction_unassigned":
        resources[0]["effective_restriction_assigned"] = False
    elif case == "restriction_noncompliant":
        resources[0]["restriction_compliant"] = False
    assert t.evaluate(t.sw.GEO, row, ev) == expected
