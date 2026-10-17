"""Approved key families must match Azure's complete JWK type names."""
import base64
import copy

import pytest

from peaso.checks import evaluate_check

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"

CID = 'azure.other.vault_key_approved_algorithm'


def assess(kty, *, bits=2048, curve='P-256', enabled=True):
    rid = SCOPE + '/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/vault/keys/key'
    key = {'id': rid + '/versions/current', 'attributes': {}, 'encryption_use': True,
           'algorithm_policy_approved': True, 'import_provenance': 'generated'}
    data = {'id': rid, 'versions': [key], '_coverage': {'versions': {'status': 'collected'}}}
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
              'created_at': '2026-10-15T00:00:00Z', 'metadata': {'compliance_policy': {'sw32': {
                  'status': 'collected', 'scope': SCOPE, 'approved_key_algorithms': {
                      'industry_standard_confirmed': True, 'minimum_rsa_bits': 2048,
                      'approved_ec_curves': ['P-256']}}}}},
             'collections': {'vault_key': [{'type': 'vault_key', 'scope': SCOPE, 'status': 'collected', 'items': [data]}]},
             'vault_key': [{'type': 'vault_key', 'scope': SCOPE, 'data': data}]}
    key['attributes']['enabled'] = enabled
    key['key'] = {'kty': kty, 'crv': curve,
                  'n': base64.urlsafe_b64encode((1 << (bits - 1)).to_bytes(bits // 8, 'big')).decode().rstrip('=')}
    before = copy.deepcopy(index)
    result = evaluate_check(CID, {'scope': SCOPE}, index)
    assert index == before
    return result[0]


@pytest.mark.parametrize('kty', ['RSA-invented', 'RSA-HSM-invented', 'RSA2', 'EC-invented', 'EC-HSM-invented', 'ECDSA'])
def test_unapproved_prefix_is_not_an_approved_native_type(kty):
    assert assess(kty) == 'UNKNOWN'


@pytest.mark.parametrize('kty', ['RSA', 'RSA-HSM', 'EC', 'EC-HSM'])
def test_exact_native_approved_types(kty):
    assert assess(kty) == 'PASS'


@pytest.mark.parametrize('kty', ['RSA', 'RSA-HSM'])
def test_exact_rsa_type_preserves_minimum_size(kty):
    assert assess(kty, bits=1024) == 'FAIL'


@pytest.mark.parametrize('kty', ['EC', 'EC-HSM'])
def test_exact_ec_type_preserves_curve_policy(kty):
    assert assess(kty, curve='P-192') == 'FAIL'


@pytest.mark.parametrize('kty', ['oct', 'oct-HSM'])
def test_other_types_are_unapproved(kty):
    assert assess(kty) == 'FAIL'


def test_disabled_version_remains_outside_enabled_key_policy():
    assert assess('RSA-invented', enabled=False) == 'PASS'


@pytest.mark.parametrize('kty', ['rsa', 'ec', '', 'future-family'])
def test_unrecognized_type_is_uncertain_not_a_native_compliance_failure(kty):
    assert assess(kty) == 'UNKNOWN'
