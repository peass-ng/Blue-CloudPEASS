"""VMSS full GET through the native Azure collector and registered check."""

import copy
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure
from peaso.engine import evaluate_snapshot
from tests.test_peaso_azure_bulk_native import BASE, SCOPE, Transport, parent


CHECK = 'azure_vm_1_4_5_1_d40be43'
KIND = 'Microsoft.Compute/virtualMachineScaleSets'
SCALE = BASE + KIND + '/scale'
LIST_PATH = SCOPE + '/providers/' + KIND


class RecordingTransport(Transport):
    def __init__(self, routes):
        super().__init__(routes)
        self.bodies = []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.bodies.append(body)
        return super().request(url, body=body, audience=audience)


def vmss_template(*, public=False):
    config = {'properties': {}}
    if public:
        config['properties']['publicIPAddressConfiguration'] = {
            'name': 'public', 'properties': {}}
    return {'virtualMachineProfile': {'networkProfile': {
        'networkInterfaceConfigurations': [{'properties': {
            'ipConfigurations': [config]}}]}}}


def run_case(*, public=False, get_problem=None):
    # LIST deliberately omits the network template; only GET may prove it.
    listed = parent(SCALE, KIND, {'provisioningState': 'Succeeded'})
    detail = parent(SCALE, KIND, vmss_template(public=public))
    routes = {LIST_PATH: {'value': [listed]}, SCALE: detail}
    if get_problem == 'denied':
        routes[SCALE] = azure.AzureReadError('forbidden', 403)
    elif get_problem == 'foreign_id':
        routes[SCALE] = {**detail, 'id': SCALE.replace('/scale', '/other')}
    elif get_problem == 'malformed':
        routes[SCALE] = {**detail, 'properties': []}
    elif get_problem == 'missing_template':
        routes[SCALE] = copy.deepcopy(listed)
    api = RecordingTransport(routes)
    snapshot = azure.collect({'scopes': [SCOPE.split('/')[-1]],
                              'options': {'retries': 0}},
                             ['vm', 'nic', 'vm_scale_set'], transport=api)
    findings = evaluate_snapshot(snapshot, checks=[CHECK],
                                 include_not_applicable=True)['findings']
    assert len(findings) == 1
    assert findings[0]['check_id'] == CHECK
    assert any(urlsplit(url).path == SCALE and
               parse_qs(urlsplit(url).query).get('api-version') == ['2024-07-01']
               for url in api.calls)
    # Resource Graph inventory is a read-only POST; all ARM resource reads are GETs.
    assert all(body is None or url.startswith(
        azure.ARM + '/providers/Microsoft.ResourceGraph/resources?')
        for url, body in zip(api.calls, api.bodies))
    assert all(not any(op in url.casefold() for op in (
        '/start/action', '/runcommand', '/delete', '/write')) for url in api.calls)
    return snapshot, findings[0]['status']


@pytest.mark.parametrize('public, expected', [(False, 'PASS'), (True, 'FAIL')])
def test_vmss_full_get_template_decides_public_ip(public, expected):
    snapshot, status = run_case(public=public)
    collection = next(c for c in snapshot['collections'] if c['type'] == 'vm_scale_set')
    assert collection['status'] == 'collected'
    assert collection['items'][0]['_provenance']['representation'] == 'full'
    assert collection['items'][0]['_provenance']['api_version'] == '2024-07-01'
    assert status == expected


@pytest.mark.parametrize('problem', [
    'denied', 'foreign_id', 'malformed', 'missing_template'])
def test_vmss_get_failure_or_incomplete_template_remains_unknown(problem):
    _, status = run_case(get_problem=problem)
    assert status == 'UNKNOWN'
