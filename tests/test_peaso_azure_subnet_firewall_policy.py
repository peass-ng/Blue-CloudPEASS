"""Operator applicability is never a native firewall or deployment claim."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.collectors import azure_subnet_firewall_policy as policy
from peaso.server.validation import validate_connector

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VNET = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet'
SUBNET = VNET + '/subnets/workload'


def options():
    now = datetime.now(timezone.utc)
    return {'compliance_parameters': {policy.NAMESPACE: {
        'status': 'collected', 'scope': SCOPE, 'authorized_by': 'security-owner',
        'document_id': 'subnet-scope', 'observed_at': (now-timedelta(hours=1)).isoformat(),
        'expires_at': (now+timedelta(hours=1)).isoformat(), 'subnet_ids': [SUBNET]}}}


@pytest.mark.parametrize('mutation', ['duplicate', 'foreign', 'traversal', 'query', 'encoded',
    'missing_authority', 'bad_authority', 'bad_time', 'naive_time', 'inverted_time', 'too_many',
    'bool_ids', 'observed_claim', 'empty_ids'])
def test_hosted_subnet_scope_rejects_unbound_input(mutation):
    config = options(); owner = config['compliance_parameters'][policy.NAMESPACE]
    if mutation == 'duplicate': owner['subnet_ids'].append(SUBNET.upper())
    if mutation == 'foreign': owner['subnet_ids'] = [SUBNET.replace('11111111', '33333333')]
    if mutation == 'traversal': owner['subnet_ids'] = [SUBNET.rsplit('/', 1)[0] + '/..']
    if mutation == 'query': owner['subnet_ids'] = [SUBNET + '?fake=1']
    if mutation == 'encoded': owner['subnet_ids'] = [SUBNET + '%2fother']
    if mutation == 'missing_authority': owner.pop('authorized_by')
    if mutation == 'bad_authority': owner['document_id'] = 'control\nforged'
    if mutation == 'bad_time': owner['observed_at'] = None
    if mutation == 'naive_time': owner['observed_at'] = '2026-10-16T00:00:00'
    if mutation == 'inverted_time': owner['expires_at'] = owner['observed_at']
    if mutation == 'too_many': owner['subnet_ids'] = [SUBNET + str(n) for n in range(257)]
    if mutation == 'bool_ids': owner['subnet_ids'] = [True]
    if mutation == 'observed_claim': owner['firewallDeployed'] = True
    if mutation == 'empty_ids': owner['subnet_ids'] = []
    with pytest.raises(HTTPException) as error:
        validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
                           config, SimpleNamespace(auth_mode='cognito'))
    assert error.value.status_code == 422


@pytest.mark.parametrize('mode', ['current', 'expired', 'future', 'foreign_scope', 'unlisted',
                                  'partial', 'wrong_service', 'duplicate', 'no_approval'])
def test_only_current_explicit_owner_scope_attaches_policy(mode):
    config = options(); owner = config['compliance_parameters'][policy.NAMESPACE]
    now = datetime.now(timezone.utc)
    if mode == 'expired': owner['expires_at'] = (now-timedelta(minutes=1)).isoformat()
    if mode == 'future':
        owner['observed_at'] = (now+timedelta(minutes=1)).isoformat()
    if mode == 'unlisted': owner['subnet_ids'] = [SUBNET + '-other']
    if mode == 'no_approval': config = {}
    row = {'id': SUBNET, '_policy': {'source': 'untrusted_ARM', 'inScope': True}}
    source = {'type': 'subnet', 'scope': VNET, 'service': 'Microsoft.Network',
              'status': 'collected', 'items': [row]}
    if mode == 'partial': source['status'] = 'partial'
    if mode == 'wrong_service': source['service'] = 'Microsoft.Other'
    if mode == 'duplicate': source['items'].append(deepcopy(row))
    reader = SimpleNamespace(collections=[source])
    before = deepcopy(config)
    scopes = [SCOPE] if mode != 'foreign_scope' else [SCOPE.replace('11111111', '33333333')]
    policy.project(reader, scopes, config)
    assert config == before
    if mode == 'current':
        assert row['_policy']['inScope'] is True
        assert row['_policy']['_provenance']['authority'] == 'explicit_operator_decision'
        assert not {'approved', 'deployed', 'privateIpAddresses'} & set(row['_policy'])
    else:
        assert '_policy' not in row
