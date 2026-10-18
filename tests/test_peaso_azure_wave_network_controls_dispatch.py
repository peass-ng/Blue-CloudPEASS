"""Public Azure collection with inert ARM and native route responses only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure
from peaso.collectors import azure_nsg_ingress_native as network_native
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot, plan_collection
from peaso.server.validation import validate_connector

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
VNET = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet'
SUBNET = VNET + '/subnets/workload'
NIC = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic'
VM = SCOPE + '/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm'
CHECK = 'azure.gap.network_subnet_protected_by_firewall'


def owner_policy(*, expired=False, subnet_ids=None):
    now = datetime.now(timezone.utc)
    return {'status': 'collected', 'scope': SCOPE, 'authorized_by': 'fixture-network-owner',
            'document_id': 'fixture-approved-subnet-scope',
            'observed_at': (now - timedelta(minutes=5)).isoformat(),
            'expires_at': (now - timedelta(minutes=1) if expired else now + timedelta(hours=1)).isoformat(),
            'subnet_ids': [SUBNET] if subnet_ids is None else subnet_ids}


@pytest.mark.parametrize('approved,protected,expected', [
    (True, False, 'FAIL'),
    (True, True, 'UNKNOWN'),
    (False, False, 'UNKNOWN'),
    ('expired', False, 'UNKNOWN'),
])
def test_public_collect_snapshot_route_and_operator_scope(monkeypatch, approved, protected, expected):
    objects = {
        VNET: {'id': VNET, 'type': 'Microsoft.Network/virtualNetworks',
               'properties': {'subnets': [{'id': SUBNET}]}},
        SUBNET: {'id': SUBNET, 'type': 'Microsoft.Network/virtualNetworks/subnets',
                 'properties': {'ipConfigurations': [{'id': NIC + '/ipConfigurations/ipconfig1'}]}},
        NIC: {'id': NIC, 'type': 'Microsoft.Network/networkInterfaces',
              'properties': {'virtualMachine': {'id': VM},
                  'ipConfigurations': [{'id': NIC + '/ipConfigurations/ipconfig1',
                                        'properties': {'subnet': {'id': SUBNET}}}]}},
        VM: {'id': VM, 'type': 'Microsoft.Compute/virtualMachines',
             'properties': {'networkProfile': {'networkInterfaces': [{'id': NIC}]}}},
    }
    requests = []
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def request(self, url, *, body=None, audience=azure.ARM):
            assert audience == azure.ARM
            path = urlsplit(url).path
            requests.append((path, deepcopy(body)))
            if path == '/providers/Microsoft.ResourceGraph/resources':
                assert isinstance(body, dict)
                return {'data': [deepcopy(objects[key]) for key in (VNET, NIC, VM)]}
            if path == SCOPE + '/resources':
                return {'value': [deepcopy(objects[key]) for key in (VNET, NIC, VM)]}
            if path in objects:
                return deepcopy(objects[path])
            for kind in ('vnet', 'nic', 'vm'):
                endpoint = azure.ENDPOINTS[kind][0]
                if path.casefold() == (SCOPE + '/providers/' + endpoint).casefold():
                    return {'value': [deepcopy(row) for row in objects.values()
                            if row['type'].casefold() == endpoint.casefold()]}
            return {'value': []}

    transport = Transport()
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda connector, kinds:
                        original(connector, kinds, transport=transport))
    route_queries = []
    def route_response(self, url, parent, kind, nsg_ids, *, initial, body=None):
        assert kind == 'routes' and parent.casefold() == NIC.casefold()
        assert initial and body is None
        route_queries.append(parent)
        routes = [{'state': 'Active', 'addressPrefix': ['0.0.0.0/0'],
                   'nextHopType': 'Internet', 'nextHopIpAddress': []}]
        if protected:
            routes.append({'state': 'Active', 'addressPrefix': ['0.0.0.0/1', '128.0.0.0/1'],
                           'nextHopType': 'VirtualAppliance', 'nextHopIpAddress': ['10.0.0.4']})
        return network_native.ReadResponse(200, {'value': routes}, {})
    monkeypatch.setattr(network_native.NetworkQueries, '_response', route_response)
    parameters = {}
    if approved:
        parameters['azure_subnet_firewall'] = owner_policy(expired=approved == 'expired')
    options = {'retries': 0, 'concurrency': 1,
               'inventories': ['subnet', 'subnet_effective_route']}
    if parameters:
        options['compliance_parameters'] = parameters
    request = {'connector': {'provider': 'azure', 'scopes': [SCOPE.rsplit('/', 1)[1]],
               'auth': {'method': 'token', 'arm_token': 'INERT-NOT-A-CREDENTIAL'},
               'options': options}, 'checks': [CHECK]}
    validate_connector('azure', request['connector']['auth'], options,
                       SimpleNamespace(auth_mode='local'))
    requirements = plan_collection(request)
    assert {'subnet', 'subnet_effective_route'}.issubset(set(requirements))
    snapshot = collect_snapshot(request)
    route_facts = [c for c in snapshot['collections'] if c['type'] == 'subnet_effective_route']
    active_approval = approved is True
    if active_approval:
        assert route_facts and route_facts[0]['status'] == 'collected', [
            (c['type'], c['scope'], c['status'], c.get('error')) for c in snapshot['collections']]
        assert len(route_queries) == 1
    else:
        assert not route_queries
        assert not any(path.casefold().endswith(('/networkinterfaces', '/virtualmachines'))
                       or path.casefold() in (NIC.casefold(), VM.casefold()) for path, _ in requests)
        assert not route_facts or all(c['status'] not in ('collected', 'empty') for c in route_facts)
    assert any(path == '/providers/Microsoft.ResourceGraph/resources' for path, _ in requests)
    if active_approval:
        fact = route_facts[0]['items'][0]
        witness = fact['nicEvidence'][0]['directInternetWitness']
        assert (witness is None) == protected
    finding = next(row for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
                   if row['check_id'] == CHECK)
    assert finding['status'] == expected, finding['evidence']
    if expected == 'FAIL':
        assert finding['evidence']['bypass_destinations'][0][1] == '1.1.1.1'
    else:
        assert 'bypass_destinations' not in finding['evidence']
