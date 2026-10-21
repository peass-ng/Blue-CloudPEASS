"""Azure network absence is based on bound, full native GETs."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso import checks
from peaso import unused_network_azure_20261021 as azure_checks
from peaso.checks.fixtures import CASES

SUBNET = 'azure.network.subnet_has_consumer_or_reservation_reference'
BALANCER = 'azure.network.load_balancer_backend_pools_have_declaration_or_consumer'


def test_bound_cases_and_incomplete_evidence():
    registered = {check.id: check for check in checks.CHECKS}
    for ident in (SUBNET, BALANCER):
        case = CASES[ident]
        check = registered[ident]
        assert check.evaluate(case['pass'], deepcopy(case['pass_index']))[0] == 'PASS'
        assert check.evaluate(case['fail'], deepcopy(case['fail_index']))[0] == 'FAIL'
        for mutation in ('partial', 'foreign_credential', 'list_only'):
            index = deepcopy(case['fail_index'])
            item = index[check.kind][0]['data']
            if mutation == 'partial':
                index['collections'][check.kind][0]['status'] = 'partial'
            elif mutation == 'foreign_credential':
                item['_provenance']['credential_context_id'] = '0' * 32
            else:
                item['_provenance']['representation'] = 'list'
            assert check.evaluate(item, index)[0] == 'UNKNOWN'


def test_subnet_reservation_and_balancer_rule_consumers():
    subnet_case = CASES[SUBNET]
    subnet = deepcopy(subnet_case['fail'])
    subnet['properties']['serviceAssociationLinks'] = [{'id': subnet['id'] + '/serviceAssociationLinks/app'}]
    index = deepcopy(subnet_case['fail_index'])
    index['collections']['subnet'][0]['items'] = [subnet]
    index['subnet'][0]['data'] = subnet
    assert azure_checks.subnet(subnet, index)[0] == 'PASS'

    lb_case = CASES[BALANCER]
    lb = deepcopy(lb_case['fail'])
    pool = lb['properties']['backendAddressPools'][0]['id']
    lb['properties']['outboundRules'] = [{'id': lb['id'] + '/outboundRules/out',
        'properties': {'backendAddressPool': {'id': pool}}}]
    index = deepcopy(lb_case['fail_index'])
    index['collections']['load_balancer'][0]['items'] = [lb]
    index['load_balancer'][0]['data'] = lb
    assert azure_checks.load_balancer(lb, index)[0] == 'PASS'


@pytest.mark.parametrize('ident,kind', [(SUBNET, 'subnet'), (BALANCER, 'load_balancer')])
def test_normal_collector_get_snapshot_finding(ident, kind):
    from peaso.collectors import azure
    from peaso.engine import evaluate_snapshot
    case = CASES[ident]
    scope = '/'.join(case['fail']['id'].split('/')[:3])
    item = deepcopy(case['fail'])
    tenant = '11111111-1111-4111-8111-111111111111'
    parent = deepcopy(case['fail_index']['collections']['vnet'][0]['items'][0]) if kind == 'subnet' else None
    class Transport:
        verified_tenant = tenant
        def __init__(self):
            self.tenant = tenant
            self.calls = []
        def request(self, url, *, body=None, audience='https://management.azure.com'):
            assert body is None
            path = urlsplit(url).path.casefold()
            self.calls.append(path)
            if path == item['id'].casefold(): return {k: deepcopy(v) for k, v in item.items() if k != '_provenance'}
            if parent and path == parent['id'].casefold(): return {k: deepcopy(v) for k, v in parent.items() if k != '_provenance'}
            if parent and path == (scope + '/providers/Microsoft.Network/virtualNetworks').casefold():
                return {'value': [{k: deepcopy(v) for k, v in parent.items() if k != '_provenance'}]}
            if kind == 'load_balancer' and path == (scope + '/providers/Microsoft.Network/loadBalancers').casefold():
                return {'value': [{k: deepcopy(v) for k, v in item.items() if k != '_provenance'}]}
            if path == '/providers/microsoft.management/managementgroups': return {'value': []}
            raise AssertionError('Unexpected read: ' + path)
    transport = Transport()
    snap = azure.collect({'provider': 'azure', 'scopes': [scope], 'auth': {'tenant_id': tenant},
        'options': {'inventories': [kind], 'concurrency': 1, 'retries': 0}}, transport=transport)
    collections = [c for c in snap['collections'] if c['type'] == kind]
    assert collections and collections[0]['status'] == 'collected', collections
    assert collections[0]['items'][0]['_provenance']['source_operation'] == 'get'
    assert collections[0]['items'][0]['_provenance']['representation'] == 'full'
    assert transport.calls.count(item['id'].casefold()) == 1
    report = evaluate_snapshot(snap, categories=['hardening'], checks=[ident])
    findings = [f for f in report['findings'] if f['check_id'] == ident]
    assert len(findings) == 1 and findings[0]['status'] == 'FAIL', findings
