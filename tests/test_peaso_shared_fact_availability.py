"""Shared fact authority and native omission regressions."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check
from peaso.checks.facts import FIELD_SPECS, Unavailable, get, guard, omitted, optional
from peaso.checks.fixtures import CASES


FIELD_PATHS = {
    "aws.ebs.encryption": "Encrypted",
    "gcp.network.custom_subnets": "autoCreateSubnetworks",
    "gcp.gke.secrets_encryption": "databaseEncryption.state",
}
FIELD_IDS = tuple(FIELD_PATHS)


@pytest.mark.parametrize("check_id", FIELD_IDS)
@pytest.mark.parametrize("fixture_status", ("pass", "fail"))
def test_explicit_null_collection_status_cannot_authorize_field_check(check_id, fixture_status):
    item = deepcopy(CASES[check_id][fixture_status])
    assert evaluate_check(check_id, item)[0] == fixture_status.upper()
    item["collection_status"] = None
    assert evaluate_check(check_id, item)[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", FIELD_IDS)
@pytest.mark.parametrize("fixture_status", ("pass", "fail"))
def test_empty_coverage_cannot_authorize_retained_selected_value(check_id, fixture_status):
    item = deepcopy(CASES[check_id][fixture_status])
    path = FIELD_PATHS[check_id]
    node = item
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    node["_coverage"] = {parts[-1]: {"status": "empty"}}
    assert evaluate_check(check_id, item)[0] == "UNKNOWN"


def test_valid_empty_list_and_native_omission_boundary():
    check_id = "gcp.sql.restrict_authorized_networks"
    item = deepcopy(CASES[check_id]["pass"])
    item["settings"]["ipConfiguration"]["_coverage"] = {
        "authorizedNetworks": {"status": "empty"}}
    assert evaluate_check(check_id, item)[0] == "PASS"
    assert optional({}, "auditLogConfigs", [], list) == []
    with pytest.raises(Unavailable):
        optional({"auditLogConfigs": None}, "auditLogConfigs", [], list)
    with pytest.raises(Unavailable):
        optional({"_coverage": {"auditLogConfigs": {"status": "empty"}}},
                 "auditLogConfigs", [], list)


def test_explicit_native_null_is_distinct_from_null_collection_metadata():
    assert get({"nativeField": None}, "nativeField") is None
    assert optional({"nativeField": None}, "nativeField", "fallback") is None
    with pytest.raises(Unavailable):
        get({"nativeField": None}, "nativeField", list)


def test_registered_gke_network_policy_native_omission_and_null():
    check_id = "gcp.gke.network_policy"
    omitted_policy = {"addonsConfig": {"networkPolicyConfig": {"disabled": True}}}
    assert evaluate_check(check_id, omitted_policy)[0] == "FAIL"
    assert evaluate_check(check_id, {**omitted_policy, "networkPolicy": None})[0] == "UNKNOWN"


@pytest.mark.parametrize("status", ("collected", "empty"))
def test_valid_and_absent_collection_status_markers(status):
    guard({})
    guard({"collection_status": status})
    with pytest.raises(Unavailable):
        guard({"collection_status": None})


@pytest.mark.parametrize("value, expected", (
    ([], list), ({}, dict), (None, None), ("", str),
))
def test_empty_coverage_coherent_value_shapes(value, expected):
    item = {"nativeField": value, "_coverage": {"nativeField": {"status": "empty"}}}
    assert get(item, "nativeField", expected) == value
    assert optional(item, "nativeField", "fallback", expected) == value


@pytest.mark.parametrize("value, expected", (
    (True, bool), (False, bool), (1, int), (0, int),
    (["retained"], list), ({"retained": True}, dict), ("retained", str),
))
def test_empty_coverage_rejects_retained_values(value, expected):
    item = {"nativeField": value, "_coverage": {"nativeField": {"status": "empty"}}}
    with pytest.raises(Unavailable):
        get(item, "nativeField", expected)
    with pytest.raises(Unavailable):
        optional(item, "nativeField", "fallback", expected)


@pytest.mark.parametrize("value, expected", (
    (True, bool), (1, int), (["retained"], list), ({"retained": True}, dict),
    (None, None),
))
def test_collected_coverage_allows_native_values(value, expected):
    item = {"nativeField": value, "_coverage": {"nativeField": {"status": "collected"}}}
    assert get(item, "nativeField", expected) == value


@pytest.mark.parametrize("expected", (bool, int, list, dict))
def test_typed_null_remains_unavailable(expected):
    for item in ({"nativeField": None},
                 {"nativeField": None, "_coverage": {"nativeField": {"status": "empty"}}}):
        with pytest.raises(Unavailable):
            get(item, "nativeField", expected)


@pytest.mark.parametrize("check_id", tuple(FIELD_SPECS))
@pytest.mark.parametrize("fixture_status", ("pass", "fail"))
def test_registered_scalar_field_check_canonical_fixtures(check_id, fixture_status):
    assert evaluate_check(check_id, deepcopy(CASES[check_id][fixture_status]))[0] == fixture_status.upper()


@pytest.mark.parametrize("value, expected", (
    ([], list), ({}, dict), (None, None), ("", str),
))
def test_omitted_accepts_coherent_empty_selected_value(value, expected):
    item = {"_provenance": {"representation": "full"}, "nativeField": value,
            "_coverage": {"nativeField": {"status": "empty"}}}
    assert omitted(item, "nativeField", "fallback", expected) == value


def test_omitted_rejects_retained_selected_value_but_preserves_documented_default():
    full = {"_provenance": {"representation": "full"}}
    assert omitted(full, "purpose", "PRIVATE", str) == "PRIVATE"
    item = {**full, "purpose": "REGIONAL_MANAGED_PROXY",
            "_coverage": {"purpose": {"status": "empty"}}}
    with pytest.raises(Unavailable):
        omitted(item, "purpose", "PRIVATE", str)
    assert evaluate_check("gcp.reviewed.network.flow_logs", item)[0] == "UNKNOWN"
    with pytest.raises(Unavailable):
        omitted({**full, "nativeField": None}, "nativeField", [], list)


@pytest.mark.parametrize("check_id", FIELD_IDS)
def test_explicit_null_selected_coverage_entry_is_unavailable(check_id):
    item = deepcopy(CASES[check_id]["pass"])
    parts = FIELD_PATHS[check_id].split(".")
    node = item
    for part in parts[:-1]:
        node = node[part]
    node["_coverage"] = {parts[-1]: None}
    assert evaluate_check(check_id, item)[0] == "UNKNOWN"


def test_omitted_rejects_explicit_null_coverage_entry_but_allows_absence():
    full = {"_provenance": {"representation": "full"}, "purpose": "PRIVATE"}
    assert omitted(full, "purpose", "PRIVATE", str) == "PRIVATE"
    with pytest.raises(Unavailable):
        omitted({**full, "_coverage": {"purpose": None}}, "purpose", "PRIVATE", str)
