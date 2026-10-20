"""A complete handler-field projection is sufficient for its declared settings."""
from copy import deepcopy

import pytest

from peaso.collectors.gcp import ReadError
from peaso.collectors.gcp_appengine_versions import SERVICES_FIELDS, VERSIONS_FIELDS
from peaso.engine import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot
from tests.test_gcp_firewall_port_native_matrix_review_20261020 import forbid_provider_network

CID = 'gcp.appengine.version_https_only'
SERVICE = 'apps/p-one/services/default'


def capture(handlers, *, fault=None, status='SERVING'):
    version = {'name': SERVICE + '/versions/v1', 'id': 'v1', 'servingStatus': status}
    if handlers is not None: version['handlers'] = deepcopy(handlers)
    def resolve(request):
        assert request['method'] == 'GET'
        if request['url'] == 'https://appengine.googleapis.com/v1/apps/p-one/services':
            assert request['params']['fields'] == SERVICES_FIELDS
            return {'services': [{'name': SERVICE, 'id': 'default'}]}
        assert request['url'] == 'https://appengine.googleapis.com/v1/' + SERVICE + '/versions'
        assert request['params']['view'] == 'FULL' and request['params']['fields'] == VERSIONS_FIELDS
        if fault == 'denied': raise ReadError('denied', 'permission_denied', http_status=403)
        if fault == 'partial': return {'versions': [version], 'nextPageToken': 'not-read'}
        return {'versions': [version]}
    collected, _ = snapshot(['app_engine_service', 'app_engine_version'], resolve, max_pages=1)
    collection = next(c for c in collected['collections'] if c['type'] == 'app_engine_version')
    if fault in ('wrong_mask', 'denied_field', 'wrong_parent', 'no_provenance'):
        row = collection['items'][0]
        if fault == 'wrong_mask': row['_field_mask'] = 'versions(handlers(securityLevel))'
        elif fault == 'denied_field': row.setdefault('_coverage', {})['handlers'] = {'status': 'denied'}
        elif fault == 'wrong_parent': row['serviceName'] = 'apps/foreign/services/default'
        else: row['_provenance']['representation'] = 'unknown'
        collected.pop('snapshot_id', None)
    before = deepcopy(collected)
    rows = evaluate_snapshot(collected, checks=[CID])['findings']
    assert collected == before
    if fault == 'partial':
        assert rows and all(row['status'] == 'UNKNOWN' for row in rows)
    else:
        assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize('handlers,expected', [
    ([{'securityLevel': 'SECURE_ALWAYS'}], 'PASS'),
    ([{'securityLevel': 'SECURE_ALWAYS'}, {'securityLevel': 'SECURE_ALWAYS'}], 'PASS'),
    ([{'securityLevel': 'SECURE_ALWAYS'}, {'securityLevel': 'SECURE_OPTIONAL'}], 'FAIL'),
    ([{'securityLevel': 'SECURE_NEVER'}], 'FAIL'),
    ([{'securityLevel': 'SECURE_DEFAULT'}], 'FAIL'),
    ([{'securityLevel': 'FUTURE'}], 'UNKNOWN'), ([], 'UNKNOWN'), (None, 'UNKNOWN'),
    ([{}], 'UNKNOWN'), ([{'securityLevel': False}], 'UNKNOWN'),
])
def test_every_native_handler_level_is_assessed(handlers, expected):
    assert capture(handlers)['status'] == expected


@pytest.mark.parametrize('fault', ['wrong_mask', 'denied_field', 'wrong_parent', 'no_provenance', 'denied', 'partial'])
def test_unproved_handler_projection_cannot_pass(fault):
    assert capture([{'securityLevel': 'SECURE_ALWAYS'}], fault=fault)['status'] in {'UNKNOWN', 'DENIED'}


def test_stopped_version_does_not_claim_active_http_exposure():
    assert capture([{'securityLevel': 'SECURE_NEVER'}], status='STOPPED')['status'] == 'NOT_APPLICABLE'
