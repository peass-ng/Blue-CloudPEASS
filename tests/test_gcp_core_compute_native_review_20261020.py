"""Native Compute inventory projection and strict deciding-field review."""
from copy import deepcopy

import pytest

from peaso.collectors.gcp import ReadError
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

P = 'https://compute.googleapis.com/compute/v1/projects/p-one'
FIELDS = ['enableVtpm', 'enableIntegrityMonitoring', 'enableSecureBoot']
SLUGS = ['shielded_vtpm', 'integrity_monitoring', 'secure_boot']


def capture(cid, kind, fragment, fault=None):
    item = {'name': 'review', **deepcopy(fragment)}
    if kind == 'instance':
        item['zone'] = P + '/zones/us-central1-a'
    if kind == 'subnetwork':
        item.update(region=P + '/regions/us-central1', network=P + '/global/networks/review')
    paths = {'instance': '/aggregated/instances', 'network': '/global/networks',
             'subnetwork': '/aggregated/subnetworks'}
    def resolve(request):
        assert request['method'] == 'GET'
        if kind == 'subnetwork' and request['url'] == P + '/regions/us-central1/subnetworks/review/getIamPolicy':
            return {'version': 3, 'bindings': []}
        assert request['url'] == P + paths[kind]
        if fault == 'denied_inventory':
            raise ReadError('denied', 'permission_denied', http_status=403)
        if kind == 'network': return {'items': [item]}
        return {'items': {'zones/us-central1-a' if kind == 'instance' else 'regions/us-central1':
                          {kind + 's': [item]}}}
    collected, transport = snapshot([kind], resolve)
    if fault and fault != 'denied_inventory':
        row = collected['collections'][0]['items'][0]
        bits = fault.split('.')
        for bit in bits[:-1]: row = row[int(bit)] if isinstance(row, list) else row[bit]
        row.setdefault('_coverage', {})[bits[-1]] = {'status': 'denied'}
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    findings = evaluate_snapshot(collected, checks=[cid])['findings']
    assert len(findings) == 1 and len(transport.requests) == (2 if kind == 'subnetwork' and fault != 'denied_inventory' else 1) and collected == before
    return findings[0]


@pytest.mark.parametrize('field,slug', zip(FIELDS, SLUGS))
@pytest.mark.parametrize('branch,expected', [('enabled', 'PASS'), ('disabled', 'FAIL'),
    ('absent', 'UNKNOWN'), ('wrong_type', 'UNKNOWN'), ('denied_field', 'UNKNOWN'),
    ('denied_inventory', 'DENIED')])
def test_native_shielded_instance_declarations(field, slug, branch, expected):
    config = {} if branch == 'absent' else {field: 'true' if branch == 'wrong_type' else branch != 'disabled'}
    fault = 'shieldedInstanceConfig.' + field if branch == 'denied_field' else branch if branch == 'denied_inventory' else None
    assert capture('gcp.compute.' + slug, 'instance', {'shieldedInstanceConfig': config}, fault)['status'] == expected


@pytest.mark.parametrize('interfaces,expected', [
    ([{'name': 'nic0'}], 'PASS'),
    ([{'accessConfigs': [{'natIP': '8.8.8.8'}]}], 'FAIL'),
    ([{'ipv6AccessConfigs': [{'externalIpv6': '2600:1901:0:1::1'}]}], 'FAIL'),
    ([{'name': 'nic0'}, {'accessConfigs': [{'natIP': '8.8.8.8'}]}], 'FAIL'),
    ([{'accessConfigs': [{'natIP': 'invalid'}]}], 'UNKNOWN'),
    ([{'accessConfigs': [{'natIP': '2600:1901:0:1::1'}]}], 'UNKNOWN'),
])
def test_native_external_addresses_include_every_interface_and_family(interfaces, expected):
    assert capture('gcp.compute.no_external_ip', 'instance', {'networkInterfaces': interfaces})['status'] == expected


@pytest.mark.parametrize('fault', ['networkInterfaces', 'networkInterfaces.0.accessConfigs', 'denied_inventory'])
def test_unreadable_external_address_inventory_is_not_absence(fault):
    fragment = {'networkInterfaces': [{'name': 'nic0'}]}
    expected = 'DENIED' if fault == 'denied_inventory' else 'UNKNOWN'
    assert capture('gcp.compute.no_external_ip', 'instance', fragment, fault)['status'] == expected


@pytest.mark.parametrize('value,expected', [(False, 'PASS'), (True, 'FAIL'), ('false', 'UNKNOWN')])
def test_native_network_subnet_creation_mode(value, expected):
    assert capture('gcp.network.custom_subnets', 'network', {'autoCreateSubnetworks': value})['status'] == expected


@pytest.mark.parametrize('purpose,enabled,expected', [
    (None, True, 'PASS'), (None, False, 'FAIL'), ('PRIVATE', True, 'PASS'),
    ('PRIVATE', False, 'FAIL'), ('REGIONAL_MANAGED_PROXY', False, 'NOT_APPLICABLE'),
    ('PRIVATE_SERVICE_CONNECT', False, 'NOT_APPLICABLE'), ('FUTURE', True, 'UNKNOWN'),
])
def test_native_private_google_access_applicability(purpose, enabled, expected):
    row = {'privateIpGoogleAccess': enabled}
    if purpose is not None: row['purpose'] = purpose
    assert capture('gcp.subnetwork.private_google_access', 'subnetwork', row)['status'] == expected


@pytest.mark.parametrize('field', ['purpose', 'privateIpGoogleAccess'])
def test_unreadable_subnet_facts_cannot_select_an_exemption(field):
    row = {'purpose': 'PRIVATE', 'privateIpGoogleAccess': True}
    assert capture('gcp.subnetwork.private_google_access', 'subnetwork', row, field)['status'] == 'UNKNOWN'
