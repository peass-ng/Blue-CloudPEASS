"""Real prepare/revalidation/consumer functions with synthetic metadata reads."""
from copy import deepcopy
from types import FunctionType, SimpleNamespace

import pytest

from test_multicontainer_declared_images import multi
from gcp_cloudrun_portable_fixtures import planner
from peaso.collectors import gcp_cloudrun_image_inspection as bridge


def proof_fixture(change=False):
    data = multi()
    reads = {**data['service_reads'], **data['revision_reads']}
    ledger = []
    def read(collector, request, *, fresh=False):
        assert request['method'] == 'GET'
        body = deepcopy(reads[request['url']])
        if fresh and change:
            body['metadata']['uid'] = 'recreated-service'
        ident = 'request-' + str(len(ledger) + 1)
        ledger.append({'id': ident, 'scope': data['scope'], 'method': 'GET',
            'status': 'collected', 'url': request['url'], 'http_attempts': 1,
            'query': {'fields': request['params']['fields']}})
        return {'url': request['url'], 'fields': request['params']['fields'],
                'source_request': ident, 'body': body}
    globals = {**vars(bridge), 'planner': planner, '_read': read}
    functions = {}
    for name in ('prepare', 'finish', 'validate_proof'):
        original = getattr(bridge, name)
        functions[name] = FunctionType(original.__code__, globals, name,
                                      original.__defaults__, original.__closure__)
    collector = SimpleNamespace(scopes=[data['scope']],
        options={'selected_cloudrun_services': data['services']},
        transport=SimpleNamespace(check_cancelled=lambda: None))
    plan, proof = functions['prepare'](collector, data['scope'], data['image_rows'],
        data['repositories'], data['projects'])
    return data, collector, functions, ledger, plan, proof


def test_all_sidecar_paths_are_reconstructed_by_actual_native_proof_consumer():
    data, collector, functions, ledger, plan, proof = proof_fixture()
    completed = functions['finish'](collector, proof)
    assert len(ledger) == 5  # service + all three active revisions + fresh service
    for row in data['image_rows']:
        row[bridge.MARKER] = deepcopy(completed)
        row['_provenance'] = {'scope': data['scope'], 'source_requests': [entry['id'] for entry in ledger]}
        paths = functions['validate_proof'](row,
            {'context': {'scope': data['scope'], 'metadata': {'source_requests': ledger}}},
            data['image_rows'], data['repositories'], data['projects'])
        assert len(paths) == 3
        assert all(path['runtime_image_proven'] is False for path in paths)
    assert len(plan['selected_artifact_images']) == 2


def test_service_recreation_rejects_multicontainer_plan_after_inspection():
    _, collector, functions, _, _, proof = proof_fixture(change=True)
    with pytest.raises(ValueError, match='service changed'):
        functions['finish'](collector, proof)


def test_deleted_sidecar_receipt_owner_is_not_valid_evidence():
    data, collector, functions, ledger, _, proof = proof_fixture()
    completed = functions['finish'](collector, proof)
    row = data['image_rows'][1]
    row[bridge.MARKER] = completed
    row['_provenance'] = {'scope': data['scope'], 'source_requests': []}
    with pytest.raises(ValueError, match='source request ownership'):
        functions['validate_proof'](row,
            {'context': {'scope': data['scope'], 'metadata': {'source_requests': ledger}}},
            data['image_rows'], data['repositories'], data['projects'])
