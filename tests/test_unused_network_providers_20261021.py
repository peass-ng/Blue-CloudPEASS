"""Source-bound unused-network signals through the normal evaluation engine."""
from copy import deepcopy

import pytest

from peaso import unused_network_azure_20261021 as azure
from peaso import unused_network_k8s_20261021 as k8s


def _registered():
    from peaso import checks
    ids = {row.id for row in checks.CHECKS}
    if azure.DECLARATIONS[0][0] not in ids:
        azure.install(checks)
    if k8s.DECLARATIONS[0][0] not in ids:
        k8s.install(checks)
    return {row.id: row for row in checks.CHECKS}


@pytest.mark.parametrize('module', [azure, k8s])
def test_hash_bound_native_pass_fail_unknown_cases(module):
    from peaso.checks.fixtures import CASES
    registered = _registered()
    for declaration in module.DECLARATIONS:
        ident = declaration[0]
        check = registered[ident]
        case = CASES[ident]
        assert check.category == 'hardening'
        assert check.evaluate(case['pass'], deepcopy(case['pass_index']))[0] == 'PASS'
        assert check.evaluate(case['fail'], deepcopy(case['fail_index']))[0] == 'FAIL'
        assert check.evaluate({}, deepcopy(case['index']))[0] == 'UNKNOWN'


@pytest.mark.parametrize('module,provider', [(azure, 'azure'), (k8s, 'k8s')])
def test_normal_engine_emits_native_hardening_finding(module, provider):
    from peaso.checks.fixtures import CASES
    from peaso.engine import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    _registered()
    for declaration in module.DECLARATIONS:
        ident = declaration[0]
        index = CASES[ident]['fail_index']
        collections = [deepcopy(row) for group in index['collections'].values() for row in group]
        snapshot = make_snapshot(provider, [index['context']['scope']], collections,
            created_at='2026-10-21T12:00:00Z', metadata=index['context'].get('metadata', {}))
        report = evaluate_snapshot(snapshot, categories=['hardening'], checks=[ident])
        findings = [f for f in report['findings'] if f['check_id'] == ident]
        assert len(findings) == 1
        assert findings[0]['status'] == 'FAIL', findings[0]


def test_selectorless_and_externalname_services_do_not_fail_as_unused():
    from peaso.checks.fixtures import CASES
    case = CASES['k8s.network.service_has_current_backend_declaration']
    index = deepcopy(case['fail_index'])
    for typ, spec in [('ExternalName', {'type': 'ExternalName', 'externalName': 'outside.example'}),
                      ('ClusterIP', {'type': 'ClusterIP'})]:
        item = deepcopy(case['fail'])
        item['spec'] = spec
        index['collections']['service'][0]['items'] = [item]
        index['service'][0]['data'] = item
        assert k8s.service(item, index)[0] == 'NOT_APPLICABLE', typ


def test_known_k8s_positives_survive_unrelated_partial_inventory():
    from peaso.checks.fixtures import CASES
    case = CASES['k8s.network.service_has_current_backend_declaration']
    index = deepcopy(case['pass_index'])
    index['collections']['pod'][0]['status'] = 'partial'
    assert k8s.service(case['pass'], index)[0] == 'PASS'
    index = deepcopy(case['fail_index'])
    index['collections']['pod'][0]['status'] = 'partial'
    with pytest.raises(ValueError):
        k8s.service(case['fail'], index)


def test_service_empty_slice_is_not_a_backend_and_address_is_positive():
    from peaso.checks.fixtures import CASES
    _registered()
    case = CASES['k8s.network.service_has_current_backend_declaration']
    index = deepcopy(case['fail_index'])
    slice_ = {
        'metadata': {'name': 'web-slice', 'namespace': 'app', 'uid': 'uid-slice',
                     'labels': {'kubernetes.io/service-name': 'web'}},
        'endpoints': [],
        'provenance': {'cluster_id': 'cluster-example', 'namespace': 'app',
                       'uid': 'uid-slice', 'evidence': 'read-only list'},
    }
    index['endpointslice'] = [{'type': 'endpointslice', 'scope': '*', 'data': slice_}]
    index['collections']['endpointslice'][0].update(status='collected', items=[slice_])
    assert k8s.service(case['fail'], deepcopy(index))[0] == 'FAIL'
    slice_['endpoints'] = [{'addresses': ['10.0.0.4']}]
    index['collections']['pod'][0]['status'] = 'partial'
    assert k8s.service(case['fail'], deepcopy(index))[0] == 'PASS'
    slice_['endpoints'] = [{'addresses': []}]
    index['collections']['pod'][0]['status'] = 'empty'
    assert k8s.service(case['fail'], deepcopy(index))[0] == 'FAIL'
    del slice_['endpoints']
    with pytest.raises(ValueError):
        k8s.service(case['fail'], deepcopy(index))


def test_legacy_endpoints_requires_managed_exact_owner_and_complete_service_list():
    from peaso.checks.fixtures import CASES
    _registered()
    case = CASES['k8s.network.endpoints_controller_service_reference_resolves']
    item, index = deepcopy(case['fail']), deepcopy(case['fail_index'])
    assert k8s.endpoints(item, deepcopy(index))[0] == 'FAIL'
    item['metadata']['labels'].clear()
    index['collections']['endpoints'][0]['items'] = [item]
    index['endpoints'][0]['data'] = item
    assert k8s.endpoints(item, deepcopy(index))[0] == 'NOT_APPLICABLE'
    item['metadata']['labels']['endpoints.kubernetes.io/managed-by'] = 'endpoint-controller'
    item['metadata']['ownerReferences'].clear()
    assert k8s.endpoints(item, deepcopy(index))[0] == 'NOT_APPLICABLE'
    item['metadata']['ownerReferences'] = deepcopy(case['fail']['metadata']['ownerReferences'])
    index['collections']['service'][0]['status'] = 'partial'
    with pytest.raises(ValueError):
        k8s.endpoints(item, deepcopy(index))
    present = deepcopy(case['pass_index'])
    service = present['collections']['service'][0]['items'][0]
    service['metadata']['uid'] = 'replacement-service-uid'
    service['provenance']['uid'] = 'replacement-service-uid'
    present['service'][0]['data'] = service
    with pytest.raises(ValueError):
        k8s.endpoints(case['pass'], present)


def test_k8s_normal_transport_to_snapshot_and_finding():
    from peaso.collectors import k8s as collector
    from peaso.engine import evaluate_snapshot
    _registered()
    calls = []

    class Api:
        server = 'https://cluster.example'

        def get_json(self, path, params=None):
            calls.append((path, dict(params or {})))
            owner = {'apiVersion': 'v1', 'kind': 'Service', 'name': 'web',
                     'uid': 'old-service-uid', 'controller': True}
            items = ({
                '/api/v1/namespaces/app/endpoints': [{
                    'apiVersion': 'v1', 'kind': 'Endpoints',
                    'metadata': {'name': 'web', 'namespace': 'app', 'uid': 'endpoint-uid',
                                 'labels': {'endpoints.kubernetes.io/managed-by': 'endpoint-controller'},
                                 'ownerReferences': [owner]}, 'subsets': []}],
                '/api/v1/namespaces/app/services': [],
            })[path]
            return {'apiVersion': 'v1', 'kind': 'EndpointsList' if path.endswith('/endpoints') else 'ServiceList',
                    'metadata': {'resourceVersion': '12'}, 'items': items}

        def close(self):
            pass

    snapshot = collector.collect({'provider': 'k8s', 'auth': {'cluster_id': 'cluster-example'},
                                  'scopes': ['app']}, ['endpoints', 'service'], api=Api())
    assert {path for path, _ in calls} == {
        '/api/v1/namespaces/app/endpoints', '/api/v1/namespaces/app/services'}
    assert all(params.get('limit') for _, params in calls)
    report = evaluate_snapshot(snapshot, categories=['hardening'],
                               checks=['k8s.network.endpoints_controller_service_reference_resolves'])
    findings = [finding for finding in report['findings'] if finding['check_id'] ==
                'k8s.network.endpoints_controller_service_reference_resolves']
    assert len(findings) == 1
    assert findings[0]['status'] == 'FAIL'


@pytest.mark.parametrize('addresses,expected', [([], 'FAIL'), (['10.0.0.4'], 'PASS')])
def test_service_backend_real_transport_to_snapshot(addresses, expected):
    from peaso.collectors import k8s as collector
    from peaso.engine import evaluate_snapshot
    _registered()
    calls = []

    class Api:
        server = 'https://cluster.example'

        def get_json(self, path, params=None):
            calls.append(path)
            items = {
                '/api/v1/namespaces/app/services': [{
                    'apiVersion': 'v1', 'kind': 'Service',
                    'metadata': {'name': 'web', 'namespace': 'app', 'uid': 'service-uid'},
                    'spec': {'type': 'ClusterIP', 'selector': {'app': 'web'}}}],
                '/api/v1/namespaces/app/pods': [],
                '/apis/discovery.k8s.io/v1/namespaces/app/endpointslices': [{
                    'apiVersion': 'discovery.k8s.io/v1', 'kind': 'EndpointSlice',
                    'metadata': {'name': 'web-slice', 'namespace': 'app', 'uid': 'slice-uid',
                                 'labels': {'kubernetes.io/service-name': 'web'}},
                    'endpoints': [{'addresses': addresses}] if addresses else []}],
            }[path]
            return {'metadata': {'resourceVersion': '12'}, 'items': items}

        def close(self):
            pass

    snapshot = collector.collect({'provider': 'k8s', 'auth': {'cluster_id': 'cluster-example'},
                                  'scopes': ['app']}, ['service', 'pod', 'endpointslice'], api=Api())
    assert set(calls) == {'/api/v1/namespaces/app/services', '/api/v1/namespaces/app/pods',
                          '/apis/discovery.k8s.io/v1/namespaces/app/endpointslices'}
    report = evaluate_snapshot(snapshot, categories=['hardening'],
                               checks=['k8s.network.service_has_current_backend_declaration'])
    findings = [finding for finding in report['findings'] if finding['check_id'] ==
                'k8s.network.service_has_current_backend_declaration']
    assert len(findings) == 1
    assert findings[0]['status'] == expected


def test_ingress_does_not_resolve_foreign_namespace_service():
    from peaso.checks.fixtures import CASES
    case = CASES['k8s.network.ingress_service_backends_resolve']
    index = deepcopy(case['pass_index'])
    service = index['collections']['service'][0]['items'][0]
    service['metadata']['namespace'] = 'elsewhere'
    service['provenance']['namespace'] = 'elsewhere'
    index['service'][0]['data'] = service
    assert k8s.ingress(case['pass'], index)[0] == 'FAIL'


def test_azure_foreign_or_partial_source_cannot_prove_absence():
    from peaso.checks.fixtures import CASES
    case = CASES['azure.network.route_table_has_subnet_reference']
    index = deepcopy(case['fail_index'])
    index['collections']['route_table'][0]['status'] = 'partial'
    with pytest.raises(ValueError):
        azure.route_table(case['fail'], index)
    index = deepcopy(case['fail_index'])
    index['route_table'][0]['data'] = {'id': 'forged'}
    with pytest.raises(ValueError):
        azure.route_table(case['fail'], index)
