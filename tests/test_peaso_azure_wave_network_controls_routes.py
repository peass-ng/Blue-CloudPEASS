"""Offline cases for the documented NIC effective-route API projection."""
from copy import deepcopy

import pytest

from peaso.collectors.azure_wave_network_controls import (
    RouteEvidenceUnavailable, project_nic_effective_routes,
)

NIC = ('/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/'
       'providers/Microsoft.Network/networkInterfaces/nic')
URL = 'https://management.azure.com' + NIC + '/effectiveRouteTable?api-version=2025-05-01'
NEXT = ('https://management.azure.com' + NIC +
        '/operationResults/22222222-2222-2222-2222-222222222222?api-version=2025-05-01')


def pages():
    return [
        {'request_url': URL, 'body': {'value': [
            {'state': 'Active', 'addressPrefix': ['0.0.0.0/0'],
             'nextHopType': 'VirtualAppliance', 'nextHopIpAddress': ['10.0.0.4']},
            {'state': 'Invalid', 'addressPrefix': ['0.0.0.0/0'],
             'nextHopType': 'Internet', 'nextHopIpAddress': []}], 'nextLink': NEXT}},
        {'request_url': NEXT, 'body': {'value': [
            {'state': 'Active', 'addressPrefix': ['203.0.113.0/24'],
             'nextHopType': 'Internet', 'nextHopIpAddress': []}]}}
    ]


def test_projects_only_active_paged_routes_without_inventing_coverage():
    projected = project_nic_effective_routes(NIC, pages())
    assert len(projected) == 2
    assert projected[0]['nextHopType'] == 'VirtualAppliance'
    assert projected[1]['destinationPrefix'] == '203.0.113.0/24'
    assert all(row['nicId'] == NIC for row in projected)
    assert all('internetBound' not in row and 'allAttachedNicsCovered' not in row for row in projected)


@pytest.mark.parametrize('mutation,reason', [
    ('missing_page', 'pagination incomplete'),
    ('wrong_page', 'pagination chain broken'),
    ('foreign_host', 'foreign URL'),
    ('foreign_nic_page', 'foreign NIC effective route continuation'),
    ('invalid_prefix', 'prefix malformed'),
    ('unknown_state', 'state unavailable'),
    ('ecmp', 'next hop unsupported'),
    ('ambiguous_hops', 'next hop ambiguous'),
    ('duplicate', 'duplicate active'),
])
def test_unprovable_route_response_raises_specific_reason(mutation, reason):
    sample = deepcopy(pages())
    if mutation == 'missing_page': sample.pop()
    elif mutation == 'wrong_page': sample[1]['request_url'] = URL
    elif mutation == 'foreign_host': sample[0]['request_url'] = URL.replace('management.azure.com', 'example.invalid')
    elif mutation == 'foreign_nic_page':
        foreign = NEXT.replace('/networkInterfaces/nic/', '/networkInterfaces/other/')
        sample[0]['body']['nextLink'] = sample[1]['request_url'] = foreign
    elif mutation == 'invalid_prefix': sample[0]['body']['value'][0]['addressPrefix'] = ['0.0.0.0/33']
    elif mutation == 'unknown_state': sample[0]['body']['value'][0]['state'] = 'Unknown'
    elif mutation == 'ecmp': sample[0]['body']['value'][0]['nextHopType'] = 'VirtualApplianceEcmp'
    elif mutation == 'ambiguous_hops': sample[0]['body']['value'][0]['nextHopIpAddress'].append('10.0.0.5')
    elif mutation == 'duplicate': sample[0]['body']['value'].append(deepcopy(sample[0]['body']['value'][0]))
    with pytest.raises(RouteEvidenceUnavailable, match=reason):
        project_nic_effective_routes(NIC, sample)
