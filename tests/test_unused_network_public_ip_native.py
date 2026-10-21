"""Normal ARM detail collection must precede a public-IP absence finding."""
from copy import deepcopy
from urllib.parse import urlsplit


def test_normal_azure_public_ip_uses_detail_get_before_finding():
    from peaso.collectors import azure
    from peaso.engine import evaluate_snapshot, hydrate_frameworks
    tenant = '11111111-1111-4111-8111-111111111111'
    scope = '/subscriptions/22222222-2222-4222-8222-222222222222'
    rid = scope + '/resourceGroups/test/providers/Microsoft.Network/publicIPAddresses/reservation'
    row = {'id': rid, 'name': 'reservation', 'type': 'Microsoft.Network/publicIPAddresses',
           'location': 'northeurope', 'properties': {'provisioningState': 'Succeeded'}}
    class Transport:
        verified_tenant = tenant
        def __init__(self): self.tenant = tenant; self.calls = []
        def request(self, url, *, body=None, audience='https://management.azure.com'):
            assert body is None
            self.calls.append(url)
            path = urlsplit(url).path.casefold()
            if path == rid.casefold(): return deepcopy(row)
            if path == (scope + '/providers/Microsoft.Network/publicIPAddresses').casefold(): return {'value': [deepcopy(row)]}
            if path == '/providers/microsoft.management/managementgroups': return {'value': []}
            raise AssertionError('Unexpected read: ' + path)
    transport = Transport()
    snap = azure.collect({'provider': 'azure', 'scopes': [scope], 'auth': {'tenant_id': tenant},
        'options': {'inventories': ['public_ip'], 'concurrency': 1, 'retries': 0}}, transport=transport)
    detail = next(c for c in snap['collections'] if c['type'] == 'public_ip')
    assert detail['status'] == 'collected', detail
    assert detail['items'][0]['_provenance']['source_operation'] == 'get'
    assert sum(urlsplit(u).path.casefold() == rid.casefold() for u in transport.calls) == 1
    report = hydrate_frameworks(evaluate_snapshot(snap, categories=['hardening'], checks=['azure.network.public_ip_has_network_reference']))
    assert len(report['findings']) == 1 and report['findings'][0]['status'] == 'FAIL', report['findings']
    assert 'HackTricks Cloud Best Practices' in report['findings'][0]['frameworks']
