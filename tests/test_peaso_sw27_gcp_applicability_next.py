"""Registered GCP checks preserve applicable failure and reject uncertain exclusions."""
import pytest

from peaso.checks import CHECKS


CHECKS_BY_ID = {check.id: check for check in CHECKS}


BUCKET = CHECKS_BY_ID["gcp.storage.no_public_iam"]
SUBNET = CHECKS_BY_ID["gcp.subnetwork.private_google_access"]
PUBLIC = {"iamPolicy": {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}}


@pytest.mark.parametrize("purpose", ["FUTURE_PURPOSE", {}, 4])
def test_unrecognized_subnet_purpose_is_unknown(purpose):
    assert SUBNET.evaluate({"privateIpGoogleAccess": True, "purpose": purpose}, {})[0] == "UNKNOWN"


def test_unreadable_subnet_purpose_is_unknown():
    item = {"privateIpGoogleAccess": True, "purpose": "REGIONAL_MANAGED_PROXY",
            "_coverage": {"purpose": {"status": "denied"}}}
    assert SUBNET.evaluate(item, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("parent", [4, [], None])
def test_malformed_prevention_parent_preserves_public_binding_fail(parent):
    assert BUCKET.evaluate({**PUBLIC, "iamConfiguration": parent}, {})[0] == "FAIL"


def test_unreadable_enforced_prevention_preserves_public_binding_fail():
    item = {**PUBLIC, "iamConfiguration": {"publicAccessPrevention": "enforced",
            "_coverage": {"publicAccessPrevention": {"status": "denied"}}}}
    assert BUCKET.evaluate(item, {})[0] == "FAIL"


def test_unreadable_prevention_parent_preserves_public_binding_fail():
    item = {**PUBLIC, "iamConfiguration": {"publicAccessPrevention": "enforced"},
            "_coverage": {"iamConfiguration": {"status": "denied"}}}
    assert BUCKET.evaluate(item, {})[0] == "FAIL"


def test_frozen_valid_cases_and_legacy_omissions():
    assert SUBNET.evaluate({"privateIpGoogleAccess": False, "purpose": "PRIVATE"}, {})[0] == "FAIL"
    assert SUBNET.evaluate({"privateIpGoogleAccess": True}, {})[0] == "PASS"
    assert SUBNET.evaluate({"privateIpGoogleAccess": False, "purpose": "REGIONAL_MANAGED_PROXY"}, {})[0] == "NOT_APPLICABLE"
    assert BUCKET.evaluate({**PUBLIC, "iamConfiguration": {"publicAccessPrevention": "enforced"}}, {})[0] == "MANUAL"
    assert BUCKET.evaluate(PUBLIC, {})[0] == "FAIL"
    assert BUCKET.evaluate({"iamPolicy": {"bindings": []}}, {})[0] == "PASS"


def test_confirmed_empty_purpose_keeps_private_default():
    item = {"privateIpGoogleAccess": False, "_coverage": {"purpose": {"status": "empty"}}}
    assert SUBNET.evaluate(item, {})[0] == "FAIL"


@pytest.mark.parametrize("purpose", ["GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER",
                                    "PRIVATE_SERVICE_CONNECT", "PRIVATE_NAT", "PEER_MIGRATION"])
def test_known_non_vm_purposes_remain_not_applicable(purpose):
    assert SUBNET.evaluate({"privateIpGoogleAccess": False, "purpose": purpose}, {})[0] == "NOT_APPLICABLE"


def test_malformed_prevention_coverage_preserves_public_binding_fail():
    item = {**PUBLIC, "iamConfiguration": {"publicAccessPrevention": "enforced",
            "_coverage": {"publicAccessPrevention": "malformed"}}}
    assert BUCKET.evaluate(item, {})[0] == "FAIL"


def test_global_resource_unavailability_remains_unknown():
    assert SUBNET.evaluate({"collection_status": "denied", "privateIpGoogleAccess": False}, {})[0] == "UNKNOWN"
    assert BUCKET.evaluate({**PUBLIC, "collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_absent_purpose_with_explicit_null_marker_is_unknown():
    item = {"privateIpGoogleAccess": True, "_coverage": {"purpose": None}}
    assert SUBNET.evaluate(item, {})[0] == "UNKNOWN"


def test_confirmed_empty_purpose_with_metadata_keeps_private_default():
    item = {"privateIpGoogleAccess": False, "_coverage": {"purpose": {
        "status": "empty", "source": "subnetwork list", "reason": "provider omitted default"}}}
    assert SUBNET.evaluate(item, {})[0] == "FAIL"


def test_malformed_coverage_map_remains_unknown():
    item = {"privateIpGoogleAccess": True, "_coverage": None}
    assert SUBNET.evaluate(item, {})[0] == "UNKNOWN"
