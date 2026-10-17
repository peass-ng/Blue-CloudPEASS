"""ASCII programmatic identifier boundary for SW23 customer-data regions."""
import pytest
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    from tests import test_peaso_compliance_new_sw23 as t


@pytest.mark.parametrize("approved,locations,expected", [
    (["WestEurope", "NorthEurope"], ["westeurope", "NORTHEUROPE"], "PASS"),
    (["WeſtEurope", "NorthEurope"], ["westeurope", "northeurope"], "UNKNOWN"),
    (["West Europe", "NorthEurope"], ["westeurope", "northeurope"], "FAIL"),
    (["West_Europe", "NorthEurope"], ["westeurope", "northeurope"], "FAIL"),
    (["westeurope", "northeurope"], ["WeſtEurope", "northeurope"], "FAIL"),
    (["westeurope", "northeurope"], ["West Europe", "northeurope"], "FAIL"),
    (["westeurope", "northeurope"], ["eastus", "northeurope"], "FAIL"),
    (["FutureRegion2", "northeurope", "westeurope"], ["futureregion2", "northeurope"], "PASS"),
])
def test_region_identifier_policy_boundary(approved, locations, expected):
    row, ev = t.fixture(t.sw.GEO)
    ev["approved_eu_regions"] = approved
    ev["customer_data_resources"]["items"][0]["locations"] = locations
    assert t.evaluate(t.sw.GEO, row, ev) == expected


def test_unicode_native_primary_region_is_unavailable():
    row, ev = t.fixture(t.sw.GEO)
    row["location"] = "WeſtEurope"
    assert t.evaluate(t.sw.GEO, row, ev) == "UNKNOWN"
