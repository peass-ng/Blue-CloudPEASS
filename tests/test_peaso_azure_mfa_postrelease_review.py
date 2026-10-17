"""Postrelease regression for signed Azure MFA selector coverage."""

import pytest

from peaso.checks import evaluate_check


CHECKS = (
    'azure.cis.multifactor_authentication_policy_exists_administrative_groups',
    'azure.cis.multifactor_authentication_policy_exists_users',
    'azure.cis.multifactor_authentication_risky_sign_ins',
)


def fixture(cid):
    scope = '/tenants/tenant-13'
    timestamp = '2026-10-12T12:00:00Z'
    policy = {'id': 'ca-1', '_provenance': {'tenant_id': 'tenant-13', 'read_only': True},
              'state': 'enabled', 'conditions': {
                  'users': {'includeUsers': ['All'], 'excludeUsers': [],
                            'includeGroups': [], 'excludeGroups': [],
                            'includeRoles': [], 'excludeRoles': []},
                  'applications': {'includeApplications': ['All'], 'excludeApplications': []},
                  'clientAppTypes': ['all'], 'locations': None, 'platforms': None,
                  'devices': None, 'signInRiskLevels': [], 'userRiskLevels': [],
                  'authenticationFlows': None},
              'grantControls': {'operator': 'AND', 'builtInControls': ['mfa'],
                                'customAuthenticationFactors': [], 'termsOfUse': [],
                                'authenticationStrength': None}}
    profile = {'id': 'profile-1', 'scope': scope,
               '_provenance': {'tenant_id': 'tenant-13', 'read_only': True},
               'userId': 'user-1', 'groupIds': ['admin-group'],
               'roleTemplateIds': [], 'membershipComplete': True,
               'pimResolved': True, 'document_id': 'inert-owner-obligation',
               'authorized_by': 'security-owner',
               'observed_at': '2026-10-01T00:00:00Z',
               'expires_at': '2026-11-01T00:00:00Z'}
    domains = {axis: [{'value': value}] for axis, value in {
        'application': 'app-1', 'clientAppType': 'browser', 'location': 'location-1',
        'platform': 'windows', 'device': 'device-1', 'signInRisk': 'medium',
        'userRisk': 'none', 'authenticationFlow': 'ordinary'}.items()}
    domains['location'][0].update(country='XX', isTrusted=False)
    domains['device'][0].update(isCompliant=True, isHybridJoined=True)
    domains['application'][0].update(isApproved=True, isCompliant=True)
    if cid == CHECKS[2]:
        domains['signInRisk'].append({'value': 'high'})
    partition = {'id': 'partition-1', 'scope': scope,
                 '_provenance': {'tenant_id': 'tenant-13', 'read_only': True},
                 'checkId': cid, 'exhaustive': True, 'userIds': ['user-1'],
                 'domains': domains,
                 'partitionProof': {axis: 'approved partition proof' for axis in domains},
                 'document_id': 'inert-owner-obligation',
                 'authorized_by': 'security-owner',
                 'observed_at': '2026-10-01T00:00:00Z',
                 'expires_at': '2026-11-01T00:00:00Z'}
    rows = {'conditional_access_policy': [policy],
            'directory_user': [{'id': 'user-1', 'accountEnabled': True,
                                '_provenance': {'tenant_id': 'tenant-13'}}],
            'conditional_access_principal': [profile],
            'conditional_access_partition': [partition],
            'named_location': [], 'authentication_strength': [],
            'directory_security_defaults': [{'id': 'defaults', 'isEnabled': False,
                                             '_provenance': {'tenant_id': 'tenant-13'}}]}
    owner = {'status': 'collected', 'scope': scope, 'authorized_by': 'security-owner',
             'document_id': 'inert-owner-obligation',
             'observed_at': '2026-10-01T00:00:00Z', 'expires_at': '2026-11-01T00:00:00Z',
             'checks': {cid.replace('.', '|'): {
                 'userScope': 'administrative' if cid == CHECKS[0] else 'all',
                 'designatedGroups': ['admin-group'], 'designatedRoles': [],
                 'requiredApplications': ['app-1'], 'requiredClientAppTypes': ['browser'],
                 'riskLicensingConfirmed': True}}}
    index = {'context': {'provider': 'azure', 'scope': scope, 'created_at': timestamp,
                         'metadata': {'compliance_policy': {'sw13': owner}}},
             'collections': {kind: [{'type': kind, 'scope': scope,
                                     'status': 'collected' if values else 'empty',
                                     'items': values}] for kind, values in rows.items()}}
    index.update({kind: [{'type': kind, 'scope': scope, 'data': row} for row in values]
                  for kind, values in rows.items()})
    return policy, index


@pytest.mark.parametrize('cid', CHECKS)
@pytest.mark.parametrize('field', (
    'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups',
    'includeGuestsOrExternalUsers', 'excludeGuestsOrExternalUsers',
))
@pytest.mark.parametrize('marker', (
    {'status': 'denied'}, {'status': 'partial'}, {'status': 'collected'},
    {'status': 'malformed'}, {'status': 'empty'}, 'malformed-marker',
))
def test_unavailable_user_selector_coverage_cannot_prove_mfa(cid, field, marker):
    item, index = fixture(cid)
    users = item['conditions']['users']
    users.pop(field, None)
    users['_coverage'] = {field: marker}
    assert evaluate_check(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', CHECKS)
@pytest.mark.parametrize('field', ('excludeUsers', 'excludeGroups', 'excludeRoles'))
def test_documented_empty_user_selector_omission_preserves_match(cid, field):
    item, index = fixture(cid)
    users = item['conditions']['users']
    users.pop(field)
    users['_coverage'] = {
        field: {'status': 'empty', 'reason': 'documented_optional_api_omission'},
    }
    assert evaluate_check(cid, item, index)[0] == 'PASS'


@pytest.mark.parametrize('cid', CHECKS)
@pytest.mark.parametrize('container,field', (
    ('conditions', 'clientApplications'),
    ('applications', 'applicationFilter'),
))
@pytest.mark.parametrize('marker', (
    {'status': 'denied'}, {'status': 'partial'}, {'status': 'collected'},
    {'status': 'malformed'}, {'status': 'empty'}, 'malformed-marker',
))
def test_unavailable_context_selector_coverage_cannot_prove_mfa(cid, container, field, marker):
    item, index = fixture(cid)
    target = item['conditions'] if container == 'conditions' else item['conditions']['applications']
    target['_coverage'] = {field: marker}
    assert evaluate_check(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', CHECKS)
@pytest.mark.parametrize('container,field', (
    ('conditions', 'clientApplications'),
    ('applications', 'applicationFilter'),
))
def test_documented_empty_context_selector_omission_preserves_match(cid, container, field):
    item, index = fixture(cid)
    target = item['conditions'] if container == 'conditions' else item['conditions']['applications']
    target['_coverage'] = {
        field: {'status': 'empty', 'reason': 'documented_optional_api_omission'},
    }
    assert evaluate_check(cid, item, index)[0] == 'PASS'


@pytest.mark.parametrize('cid', CHECKS)
@pytest.mark.parametrize('container,field', (
    ('conditions', 'locations'), ('conditions', 'platforms'),
    ('conditions', 'devices'), ('conditions', 'signInRiskLevels'),
    ('conditions', 'userRiskLevels'), ('conditions', 'authenticationFlows'),
    ('applications', 'excludeApplications'),
))
def test_documented_empty_optional_field_uses_its_empty_default(cid, container, field):
    item, index = fixture(cid)
    target = item['conditions'] if container == 'conditions' else item['conditions']['applications']
    target.pop(field)
    target['_coverage'] = {
        field: {'status': 'empty', 'reason': 'documented_optional_api_omission'},
    }
    assert evaluate_check(cid, item, index)[0] == 'PASS'


@pytest.mark.parametrize('cid', CHECKS)
def test_present_selector_with_denied_coverage_cannot_prove_mfa(cid):
    item, index = fixture(cid)
    item['conditions']['users']['_coverage'] = {'excludeUsers': {'status': 'denied'}}
    assert evaluate_check(cid, item, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('cid', CHECKS)
def test_denied_guest_exclusion_field_cannot_prove_mfa(cid):
    item, index = fixture(cid)
    assert evaluate_check(cid, item, index)[0] == 'PASS'
    item['conditions']['users']['_coverage'] = {
        'excludeGuestsOrExternalUsers': {'status': 'denied'},
    }
    assert evaluate_check(cid, item, index)[0] == 'UNKNOWN'
