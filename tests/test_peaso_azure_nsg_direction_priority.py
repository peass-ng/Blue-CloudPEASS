"""Offline regression: native NSG priorities are unique within each direction.

Paths/measurements here are explicit evaluator unit inputs, not claims of cloud
collection or observed services. Six defaults retain the documented ARM shape.
"""
from copy import deepcopy

import pytest

from peaso.checks import CHECKS

SCOPE = '/subscriptions/11111111-2222-3333-4444-555555555555'
NSG = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n'
PORTS = 'azure_nsg_world_ingress_approved_ports'
PAIRS = 'azure.other.nsg_port_protocol_assignment'


def native_nsg():
    defaults = []
    for direction, names in (
        ('Inbound', ('AllowVnetInBound', 'AllowAzureLoadBalancerInBound', 'DenyAllInBound')),
        ('Outbound', ('AllowVnetOutBound', 'AllowInternetOutBound', 'DenyAllOutBound')),
    ):
        for name, priority in zip(names, (65000, 65001, 65500)):
            defaults.append({'name': name, 'properties': {
                'priority': priority, 'direction': direction,
                'access': 'Deny' if priority == 65500 else 'Allow',
                'protocol': '*', 'sourcePortRange': '*', 'destinationPortRange': '*',
                'sourceAddressPrefix': 'VirtualNetwork' if priority == 65000 else (
                    'AzureLoadBalancer' if direction == 'Inbound' and priority == 65001 else '*'),
                'destinationAddressPrefix': 'VirtualNetwork' if priority == 65000 else (
                    'Internet' if direction == 'Outbound' and priority == 65001 else '*'),
            }})
    return {'id': NSG, 'properties': {'defaultSecurityRules': defaults,
        'securityRules': [{'name': 'AllowHttps', 'properties': {
            'priority': 100, 'direction': 'Inbound', 'access': 'Allow',
            'protocol': 'Tcp', 'sourceAddressPrefix': '*', 'sourcePortRange': '*',
            'destinationAddressPrefix': '*', 'destinationPortRange': '443'}}]}}


def evaluate(check_id, nsg=None, *, port=443, service='https', complete=True):
    nsg = native_nsg() if nsg is None else nsg
    path = {'id': NSG + '/effectiveInternetPaths/tcp443', 'parent_id': NSG,
            'properties': {'protocol': 'Tcp', 'destinationPort': port,
                           'worldSource': True, 'allowed': True}}
    measurement = {'id': path['id'] + '/measurement', 'path_id': path['id'], 'parent_id': NSG,
        'properties': {'protocol': 'Tcp', 'port': port, 'measuredService': service,
                       'ianaAssignedService': 'https'}}
    kinds = {'nsg': [nsg], 'nsg_effective_internet_path': [path],
             'nsg_service_measurement': [measurement]}
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                'created_at': '2026-10-16T01:00:00Z',
                'metadata': {'compliance_policy': {'sw31': {'approvedInternetPorts': [443]}}}},
             'collections': {kind: [{'scope': SCOPE, 'status': 'collected' if complete else 'denied',
                                      'items': deepcopy(rows)}] for kind, rows in kinds.items()},
             **{kind: [{'scope': SCOPE, 'data': deepcopy(row)} for row in rows]
                for kind, rows in kinds.items()}}
    if check_id == PAIRS:
        from tests.nsg_service_observation_fixture import authorize_fixture_index
        authorize_fixture_index(index)
    check = next(check for check in CHECKS if check.id == check_id)
    return check.evaluate({'scope': SCOPE}, index)[0]


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
def test_native_six_defaults_plus_custom_https_pass(check_id):
    row = native_nsg()
    assert len(row['properties']['defaultSecurityRules']) == 6
    assert evaluate(check_id, row) == 'PASS'


def test_unapproved_port_still_fails():
    assert evaluate(PORTS, port=22) == 'FAIL'


def test_measured_service_mismatch_still_fails():
    assert evaluate(PAIRS, service='ssh') == 'FAIL'


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
@pytest.mark.parametrize('direction', [None, '', 'inbound', 'OUTBOUND', 'Both', 1, True])
def test_missing_or_invalid_direction_unknown(check_id, direction):
    row = native_nsg()
    props = row['properties']['defaultSecurityRules'][0]['properties']
    if direction is None:
        del props['direction']
    else:
        props['direction'] = direction
    assert evaluate(check_id, row) == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
@pytest.mark.parametrize('direction', ['Inbound', 'Outbound'])
def test_same_direction_duplicate_priority_unknown(check_id, direction):
    row = native_nsg()
    rule = next(rule for rule in row['properties']['defaultSecurityRules']
                if rule['properties']['direction'] == direction)
    row['properties']['securityRules'].append(deepcopy(rule))
    assert evaluate(check_id, row) == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
@pytest.mark.parametrize('priority', [None, 99, 65501, -1, True, '100', 100.0])
def test_missing_or_invalid_priority_unknown(check_id, priority):
    row = native_nsg()
    props = row['properties']['securityRules'][0]['properties']
    if priority is None:
        del props['priority']
    else:
        props['priority'] = priority
    assert evaluate(check_id, row) == 'UNKNOWN'


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
def test_equal_custom_priority_in_opposite_directions_pass(check_id):
    row = native_nsg()
    outbound = deepcopy(row['properties']['securityRules'][0])
    outbound['properties']['direction'] = 'Outbound'
    row['properties']['securityRules'].append(outbound)
    assert evaluate(check_id, row) == 'PASS'


@pytest.mark.parametrize('check_id', [PORTS, PAIRS])
def test_incomplete_dependencies_remain_unknown(check_id):
    assert evaluate(check_id, complete=False) == 'UNKNOWN'
