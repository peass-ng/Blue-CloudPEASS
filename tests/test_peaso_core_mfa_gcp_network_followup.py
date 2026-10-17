"""Inert authority cases for MFA collection coherence and assigned IP evidence."""
from test_peaso_core_mfa_gcp_network_authority import observed, MFA, IP, LOGIN
import pytest


def test_mfa_empty_wrapper_cannot_observe_retained_device():
    assert observed(MFA, {"LoginProfile": LOGIN, "MFADevices": {"collection_status": "empty", "items": [{"SerialNumber": "mfa"}]}}) == "UNKNOWN"


def test_mfa_coherent_empty_and_observed_device():
    assert observed(MFA, {"LoginProfile": LOGIN, "MFADevices": {"collection_status": "empty", "items": []}}) == "FAIL"
    assert observed(MFA, {"LoginProfile": LOGIN, "MFADevices": {"collection_status": "collected", "items": [{"SerialNumber": "mfa"}]}}) == "PASS"


@pytest.mark.parametrize("field,key,address", [
    ("accessConfigs", "natIP", "not-an-ip"),
    ("accessConfigs", "natIP", "2001:db8::1"),
    ("ipv6AccessConfigs", "externalIpv6", "not-an-ip"),
    ("ipv6AccessConfigs", "externalIpv6", "203.0.113.1"),
])
def test_invalid_or_wrong_family_address_is_not_assigned_ip_evidence(field, key, address):
    assert observed(IP, {"networkInterfaces": [{field: [{key: address}]}]}) == "UNKNOWN"


def test_valid_assigned_addresses_remain_independent():
    assert observed(IP, {"networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.1"}, {"natIP": "not-an-ip"}]}]}) == "FAIL"
    assert observed(IP, {"networkInterfaces": [{"ipv6AccessConfigs": [{"externalIpv6": "2001:db8::1"}]}]}) == "FAIL"
