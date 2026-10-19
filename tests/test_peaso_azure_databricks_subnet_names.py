from copy import deepcopy

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import CASES, cid


@pytest.mark.parametrize("mode", ["both_missing", "private_missing", "public_missing", "empty", "duplicate", "nonstring"])
def test_custom_vnet_cannot_pass_without_two_observed_subnet_names(mode):
    ident = cid("databricks_subnet_nsg")
    check = next(c for c in CHECKS if c.id == ident)
    fixture = CASES[ident]
    item = deepcopy(fixture["pass"])
    params = item["properties"]["parameters"]
    if mode in ("both_missing", "private_missing"):
        params.pop("customPrivateSubnetName")
    if mode in ("both_missing", "public_missing"):
        params.pop("customPublicSubnetName")
    if mode == "empty":
        params["customPublicSubnetName"]["value"] = ""
    if mode == "duplicate":
        params["customPublicSubnetName"]["value"] = params["customPrivateSubnetName"]["value"]
    if mode == "nonstring":
        params["customPublicSubnetName"]["value"] = True
    assert check.evaluate(item, fixture["pass_index"])[0] == "UNKNOWN"


def test_both_distinct_subnets_and_managed_vnet_keep_existing_results():
    ident = cid("databricks_subnet_nsg")
    check = next(c for c in CHECKS if c.id == ident)
    fixture = CASES[ident]
    for name, expected in (("pass", "PASS"), ("fail", "FAIL"), ("not_applicable", "NOT_APPLICABLE")):
        assert check.evaluate(fixture[name], fixture.get(name + "_index", {}))[0] == expected
