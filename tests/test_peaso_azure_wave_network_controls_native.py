"""Existing native-route evidence projected through the public evaluator."""
from copy import deepcopy

from peaso.collectors import azure
from peaso.collectors import azure_wave_network_controls as native
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VNET = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet'
SUBNET = VNET + '/subnets/workload'
NIC = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic'
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
CHECK = 'azure.gap.network_subnet_protected_by_firewall'


def raw_routes(*, protected=False):
    routes = [{'state': 'Active', 'addressPrefix': ['0.0.0.0/0'],
               'nextHopType': 'Internet', 'nextHopIpAddress': []}]
    if protected:
        routes.append({'state': 'Active', 'addressPrefix': ['0.0.0.0/1', '128.0.0.0/1'],
                       'nextHopType': 'VirtualAppliance', 'nextHopIpAddress': ['10.0.0.4']})
    return routes


def reader(*, protected=False, reciprocal=True, source_proof=True, attached=True):
    result = azure._Reader({'concurrency': 1, 'retries': 0})
    detail = {'representation': 'full', 'source_operation': 'get',
              'read_only': True, 'api_version': '2023-09-01'}
    nic = {'id': NIC, '_provenance': deepcopy(detail),
           'properties': {'virtualMachine': {'id': VM} if attached else None,
           'ipConfigurations': [{'id': NIC + '/ipConfigurations/ipconfig1',
                                 'properties': {'subnet': {'id': SUBNET}}}]}}
    vm = {'id': VM, '_provenance': deepcopy(detail),
          'properties': {'networkProfile': {'networkInterfaces':
          [{'id': NIC}] if reciprocal else []}}}
    rows = [{'id': NIC + '/effectiveRoutes/' + str(i), 'nic_id': NIC,
             'route': route, '_provenance': {'source_operation': 'effectiveRouteTable',
             'read_only': True, 'nic_id': NIC}} for i, route in enumerate(raw_routes(protected=protected))]
    result.collections = [
        {'type': 'subnet', 'scope': VNET, 'status': 'collected',
         'items': [{'id': SUBNET, '_policy': {'source': 'approved_policy',
                    'status': 'collected', 'inScope': True}}]},
        {'type': 'nic', 'scope': SCOPE, 'status': 'collected', 'items': [nic]},
        {'type': 'vm', 'scope': SCOPE, 'status': 'collected', 'items': [vm]},
        {'type': 'effective_route', 'scope': SCOPE, 'status': 'collected',
         'items': rows, 'source_evidence': [{
             'source_operation': 'effectiveRouteTable', 'resource_id': NIC,
             'api_version': native.API_VERSION, 'read_only': True,
             'representation': 'full', 'response_sha256': 'a' * 64,
         }] if source_proof else []},
    ]
    return result


def project(**kwargs):
    result = reader(**kwargs)
    native.collect(result, [SCOPE], {'subnet_effective_route'})
    assert result.budget.calls == 0
    return result.collections


def finding(collections):
    snapshot = make_snapshot('azure', [VNET], collections)
    findings = [row for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
                if row['check_id'] == CHECK]
    assert len(findings) == 1
    return findings[0]


def test_existing_native_route_source_produces_direct_internet_counterexample():
    collections = project()
    fact = collections[-1]['items'][0]
    assert collections[-1]['status'] == 'collected'
    assert fact['nicEvidence'][0]['directInternetWitness']['destinationIp'] == '1.1.1.1'
    assert fact['allAttachedNicsCovered'] is False
    assert fact['exhaustiveInternetDestinations'] is False
    observed = finding(collections)
    assert observed['status'] == 'FAIL', observed['evidence']
    assert observed['evidence']['bypass_destinations'][0][1] == '1.1.1.1'


def test_more_specific_appliance_routes_shadow_default_internet():
    collections = project(protected=True)
    assert collections[-1]['items'][0]['nicEvidence'][0]['directInternetWitness'] is None
    observed = finding(collections)
    assert observed['status'] == 'UNKNOWN'
    assert 'effective route coverage incomplete' in observed['evidence'].get('reason', '')


def test_unproven_native_page_is_unavailable_not_a_counterexample():
    collections = project(source_proof=False)
    assert collections[-1]['status'] == 'malformed'
    assert collections[-1]['error']['kind'] == 'RouteEvidenceUnavailable'
    assert collections[-1]['items'] == []
    observed = finding(collections)
    assert observed['status'] == 'UNKNOWN'
    assert 'dependency incomplete or unavailable: subnet_effective_route' == observed['evidence'].get('reason')


def test_nonreciprocal_vm_attachment_is_unavailable():
    collections = project(reciprocal=False)
    assert collections[-1]['status'] not in ('collected', 'empty')
    assert collections[-1]['items'] == []


def test_list_only_nic_cannot_claim_active_route_attachment():
    source = reader()
    del source.collections[1]['items'][0]['_provenance']
    native.collect(source, [SCOPE], {'subnet_effective_route'})
    assert source.collections[-1]['status'] == 'malformed'
    assert source.collections[-1]['error']['kind'] == 'RouteEvidenceUnavailable'
    assert finding(source.collections)['status'] == 'UNKNOWN'


def test_unattached_nic_has_no_direct_witness():
    collections = project(attached=False)
    assert collections[-1]['status'] == 'collected'
    assert collections[-1]['items'][0]['nicEvidence'] == []
    observed = finding(collections)
    assert observed['status'] == 'UNKNOWN'
    assert 'effective route coverage incomplete' in observed['evidence'].get('reason', '')


def test_exact_subnet_identity_required_for_join():
    source = reader()
    wrong = deepcopy(source.collections[1]['items'][0])
    wrong['properties']['ipConfigurations'][0]['properties']['subnet']['id'] = (
        VNET + '/subnets/other')
    source.collections[1]['items'][0] = wrong
    native.collect(source, [SCOPE], {'subnet_effective_route'})
    assert source.collections[-1]['items'][0]['nicEvidence'] == []
    assert finding(source.collections)['status'] == 'UNKNOWN'


def test_duplicate_nic_or_ip_configuration_cannot_produce_witness():
    for duplicate in ('nic', 'ip_configuration'):
        source = reader()
        if duplicate == 'nic':
            source.collections[1]['items'].append(deepcopy(source.collections[1]['items'][0]))
        else:
            configs = source.collections[1]['items'][0]['properties']['ipConfigurations']
            configs.append(deepcopy(configs[0]))
        native.collect(source, [SCOPE], {'subnet_effective_route'})
        assert source.collections[-1]['status'] == 'malformed'
        assert source.collections[-1]['items'] == []


def test_shared_resource_cap_marks_projection_partial():
    source = reader()
    source.budget.max_items = 0
    native.collect(source, [SCOPE], {'subnet_effective_route'})
    assert source.collections[-1]['status'] == 'partial'
    assert source.collections[-1]['items'] == []
    assert source.collections[-1]['error']['code'] == 'resource_limit'
    assert finding(source.collections)['status'] == 'UNKNOWN'


def test_legacy_self_declared_complete_route_fact_is_unknown():
    item = {'id': SUBNET, '_policy': {'source': 'approved_policy',
            'status': 'collected', 'inScope': True}}
    routes = [
        {'nicId': NIC, 'destinationPrefix': '0.0.0.0/0', 'internetBound': True,
         'nextHopType': 'Internet', 'nextHopIpAddress': ''},
        *[{'nicId': NIC, 'destinationPrefix': prefix, 'internetBound': True,
            'nextHopType': 'VirtualAppliance', 'nextHopIpAddress': '10.0.0.4'}
          for prefix in ('0.0.0.0/1', '128.0.0.0/1')],
    ]
    route_fact = {'id': SUBNET + '/providers/PEASO/effectiveRoutes/full',
        'subnetId': SUBNET, '_provenance': {'source_operation':
        'networkInterfaces/getEffectiveRouteTable', 'read_only': True},
        'exhaustiveInternetDestinations': True, 'allAttachedNicsCovered': True,
        'families': ['ipv4'], 'ipv6Enabled': False, 'nicIds': [NIC],
        'internetRoutes': routes}
    firewall = {'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw',
        'kind': 'AzureFirewall', 'deployed': True, 'approved': True,
        'approvalSource': 'approved_policy', 'privateIpAddresses': ['10.0.0.4']}
    collections = [
        {'type': 'subnet', 'scope': VNET, 'status': 'collected', 'items': [item]},
        {'type': 'subnet_effective_route', 'scope': VNET, 'status': 'collected', 'items': [route_fact]},
        {'type': 'approved_firewall', 'scope': VNET, 'status': 'collected', 'items': [firewall]},
    ]
    observed = finding(collections)
    assert observed['status'] == 'UNKNOWN', observed['evidence']
