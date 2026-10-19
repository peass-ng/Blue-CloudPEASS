from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_azure_data import _ltr
from peaso.checks.fixtures import CASES
from peaso.checks.facts import Unavailable
from peaso.checks.azure_policy_periods import positive_duration, rotation_interval_supported


@pytest.mark.parametrize("value, expected", [("PT0S", False), ("P0D", False),
                                            ("P0W", False), ("P4W", True),
                                            ("P1M", True), ("P10Y", True),
                                            ("P1Y2M3D", True)])
def test_nonzero_retention_duration(value, expected):
    assert positive_duration(value) is expected


@pytest.mark.parametrize("value", ["garbage", "", "P", "PT", "P7DT", "P-1D", "P1W1D", None, 30])
def test_malformed_duration_is_not_evidence_of_configured_retention(value):
    with pytest.raises(Unavailable):
        positive_duration(value)


@pytest.mark.parametrize("value, expected", [("PT0S", "FAIL"), ("P0D", "FAIL"),
                                            ("P0W", "FAIL"), ("P4W", "PASS"),
                                            ("garbage", "UNKNOWN"), ("P-1D", "UNKNOWN")])
def test_sql_ltr_does_not_accept_arbitrary_or_zero_strings(value, expected):
    check = next(c for c in CHECKS if c.id == "azure.claude.sql_database_long_term_retention")
    assert check.evaluate(_ltr(value), {})[0] == expected


@pytest.mark.parametrize("value, expected", [("P0D", "UNKNOWN"), ("PT0S", "UNKNOWN"),
                                            ("P1D", "UNKNOWN"), ("P6D", "UNKNOWN"),
                                            ("P7D", "PASS"), ("P1M", "PASS"),
                                            ("P90D", "PASS"), ("garbage", "UNKNOWN")])
def test_key_rotation_requires_supported_positive_interval(value, expected):
    cid = "azure.port.keyvault_key_automatic_rotation_enabled"
    check = next(c for c in CHECKS if c.id == cid)
    fixture = CASES[cid]
    index = deepcopy(fixture["pass_index"])
    index["key_rotation_policy"][0]["data"]["properties"]["lifetimeActions"][0]["trigger"]["timeAfterCreate"] = value
    assert check.evaluate(fixture["pass"], index)[0] == expected


def test_rotation_month_is_not_a_fixed_thirty_day_conversion():
    assert rotation_interval_supported("P1M")
    assert rotation_interval_supported("PT168H")
    assert not rotation_interval_supported("PT167H59M59S")
