"""Immutable date boundaries, encryption applicability and real metadata gaps."""
import copy
import pytest
from peaso.checks import CHECKS, gcp_ports_keys as ports
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS if check.id in ports.IDS}


@pytest.mark.parametrize("cid", ports.IDS)
@pytest.mark.parametrize("case,wanted", [("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN"), ("denied", "UNKNOWN")])
def test_key_metadata_available_and_unavailable_truths(cid, case, wanted):
    item = {"collection_status": "denied"} if case == "denied" else copy.deepcopy(CASES[cid][case])
    index = copy.deepcopy(CASES[cid].get("index", {}))
    original = copy.deepcopy((item, index))
    actual, evidence = REGISTRY[cid].evaluate(item, index)
    assert actual == wanted, evidence
    assert (item, index) == original


def test_key_age_uses_captured_date_and_preserves_midnight_threshold():
    check = REGISTRY[ports.REFERENCE_SPECS["iam_api_key_age_90"]]
    observed = "2026-10-10T12:00:00Z"
    boundary = "2026-07-12T00:00:00Z"
    assert check.evaluate({"createTime": boundary, "_provenance": {"collected_at": observed}}, {})[0] == "FAIL"
    assert check.evaluate({"createTime": "2026-07-12T00:00:01Z", "_provenance": {"collected_at": observed}}, {})[0] == "PASS"
    assert check.evaluate({"createTime": boundary}, {})[0] == "UNKNOWN"


def test_user_managed_key_policy_does_not_apply_to_provider_keys():
    check = REGISTRY[ports.REFERENCE_SPECS["iam_service_account_key_age_90"]]
    assert check.evaluate({"keyType": "SYSTEM_MANAGED"}, {})[0] == "NOT_APPLICABLE"


def test_known_empty_api_targets_are_not_a_real_restriction():
    check = REGISTRY[ports.REFERENCE_SPECS["iam_api_key_restricts_apis"]]
    assert check.evaluate({"restrictions": {"apiTargets": []}}, {})[0] == "FAIL"
    # Exact source presence test would pass this empty array.
    assert "apiTargets" in {"apiTargets": []}


def test_ipv6_all_and_empty_caller_restrictions_remain_unrestricted():
    check = REGISTRY[ports.REFERENCE_SPECS["iam_api_key_restricts_websites_hosts_apps"]]
    for values in ([], ["::/0"]):
        assert check.evaluate({"restrictions": {"serverKeyRestrictions": {"allowedIps": values}}}, {})[0] == "FAIL"


def test_encryption_views_and_disabled_primary_versions_have_explicit_applicability():
    assert REGISTRY[ports.REFERENCE_SPECS["bigquery_table_encrypted_with_cmk"]].evaluate({"type": "VIEW"}, {})[0] == "NOT_APPLICABLE"
    assert REGISTRY[ports.REFERENCE_SPECS["kms_key_rotated_within_90_day"]].evaluate({"primary": {"state": "DISABLED"}}, {})[0] == "NOT_APPLICABLE"


def test_serviceaccount_key_absence_requires_complete_inventory_and_own_identity():
    check = REGISTRY[ports.REFERENCE_SPECS["iam_service_account_gcp_managed_key"]]
    fixture = CASES[check.id]
    assert check.evaluate(fixture["pass"], {})[0] == "UNKNOWN"
    index = copy.deepcopy(fixture["index"])
    index["collections"]["service_account_key"][0]["status"] = "partial"
    assert check.evaluate(fixture["pass"], index)[0] == "UNKNOWN"


def test_kms_period_unset_rotation_needs_full_representation_and_applicable_key():
    check = REGISTRY[ports.REFERENCE_SPECS["kms_key_rotated_within_90_day"]]
    key = {"purpose": "ENCRYPT_DECRYPT", "primary": {"state": "ENABLED"}}
    assert check.evaluate({**key, "_provenance": {"representation": "full"}}, {})[0] == "FAIL"
    assert check.evaluate(dict(key), {})[0] == "UNKNOWN"
    assert check.evaluate({**key, "_provenance": {"representation": "partial"}}, {})[0] == "UNKNOWN"
    assert check.evaluate({"purpose": "ASYMMETRIC_SIGN", "primary": {"state": "ENABLED"}, "_provenance": {"representation": "full"}}, {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({**key, "primary": {"state": "DESTROYED"}, "_provenance": {"representation": "full"}}, {})[0] == "NOT_APPLICABLE"
