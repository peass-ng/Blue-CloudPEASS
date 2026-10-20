"""Backing service joins must prove project identity before comparing suffixes."""
from copy import deepcopy

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot, plan_collection
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

SCENARIOS = ['same_project', 'numeric_reference', 'numeric_candidate', 'foreign_reference',
             'foreign_candidate', 'foreign_project_identity', 'denied_project_identity', 'public_invoker']


@pytest.mark.parametrize('slug', ['not_publicly_accessible', 'vpc_connector_configured'])
@pytest.mark.parametrize('scenario', SCENARIOS)
def test_native_backing_service_project_binding(slug, scenario):
    numeric_ref = scenario in ('numeric_reference', 'foreign_project_identity', 'denied_project_identity')
    reference = 'projects/' + ('foreign' if scenario == 'foreign_reference' else '123' if numeric_ref else 'p-one') + '/locations/us-central1/services/fn'
    candidate = 'projects/' + ('foreign' if scenario == 'foreign_candidate' else '123' if scenario == 'numeric_candidate' else 'p-one') + '/locations/us-central1/services/fn'
    function = {'name': 'projects/p-one/locations/us-central1/functions/fn', 'environment': 'GEN_2',
                'state': 'ACTIVE', 'serviceConfig': {'service': reference, 'ingressSettings': 'ALLOW_ALL'}}
    run = {'name': candidate, 'template': {}}
    before = deepcopy((function, run))

    def resolve(request):
        assert request['method'] == 'GET'
        url = request['url']
        if url == 'https://cloudfunctions.googleapis.com/v2/projects/p-one/locations/-/functions':
            return {'functions': [function]}
        if url == 'https://cloudfunctions.googleapis.com/v2/projects/p-one/locations/us-central1/functions/fn:getIamPolicy':
            return {'bindings': []}
        if url == 'https://run.googleapis.com/v2/projects/p-one/locations/us-central1/services':
            return {'services': [run]}
        if url == 'https://run.googleapis.com/v2/' + candidate + ':getIamPolicy':
            return {'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers']}]} if scenario == 'public_invoker' else {'bindings': []}
        if url == 'https://cloudresourcemanager.googleapis.com/v3/projects/p-one':
            if scenario == 'denied_project_identity': raise gcp.ReadError('denied', 'permission_denied', http_status=403)
            return {'projectId': 'foreign' if scenario == 'foreign_project_identity' else 'p-one', 'name': 'projects/123'}
        if url == 'https://compute.googleapis.com/compute/v1/projects/p-one':
            return {'kind': 'compute#project', 'name': 'p-one', 'id': '123'}
        raise AssertionError('Unplanned native endpoint: ' + url)

    collected, transport = snapshot(['function', 'cloudrun_service', 'project'], resolve,
                                    cloudrun_locations=['us-central1'], metrics_scopes=False)
    assert (function, run) == before
    original = deepcopy(collected)
    cid = 'gcp.claude2.function.' + slug
    assert set(plan_collection({'connector': {'provider': 'gcp', 'scopes': ['projects/p-one']}, 'checks': [cid]})) == {'function', 'cloudrun_service', 'project'}
    rows = evaluate_snapshot(collected, checks=[cid])['findings']
    assert len(rows) == 1 and original == collected
    expected = ('UNKNOWN' if scenario in ('foreign_reference', 'foreign_candidate', 'foreign_project_identity', 'denied_project_identity')
                else 'FAIL' if slug == 'vpc_connector_configured' or scenario == 'public_invoker' else 'PASS')
    assert rows[0]['status'] == expected, rows[0]
    if scenario.startswith('numeric'):
        assert any(r['url'] == 'https://cloudresourcemanager.googleapis.com/v3/projects/p-one' for r in transport.requests)
