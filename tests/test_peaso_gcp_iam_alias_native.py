"""Portable project IAM alias regression through the normal native collector and engine."""
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from peaso.collectors import gcp
from peaso.engine import evaluate_snapshot
from peaso.snapshot import validate

SCOPE = 'projects/fixture-project'
NUMBER = 'projects/12345'
ROOT = '//cloudresourcemanager.googleapis.com/' + SCOPE
KMS = '//cloudkms.googleapis.com/projects/12345/locations/us/keyRings/r'
CRYPTO = KMS + '/cryptoKeys/k'
CONFIGS = [{'service': 'allServices', 'auditLogConfigs': [
    {'logType': 'DATA_READ'}, {'logType': 'DATA_WRITE'}]}]
CHECK = 'gcp.iam.data_access_audit'


class NativeTransport:
    def __init__(self, *, root_name=ROOT, project=NUMBER, projected=None,
                 peer_duplicate=False, deny_cai=False, malformed_project=False, peer_name=KMS,
                 cai_next_page=False, pending_denial=False, empty_cai_page=False):
        self.root_name = root_name
        self.project = project
        self.projected = {'bindings': []} if projected is None else projected
        self.peer_duplicate = peer_duplicate
        self.peer_name = peer_name
        self.deny_cai = deny_cai
        self.malformed_project = malformed_project
        self.cai_next_page = cai_next_page
        self.pending_denial = pending_denial
        self.empty_cai_page = empty_cai_page
        self.calls = 0
        self.evidence = []

    def request(self, method, url, **kwargs):
        self.calls += 1
        ref = 'request-' + str(self.calls)
        entry = {'id': ref, 'method': method, 'url': url, 'scope': kwargs.get('scope'),
                 'status': 'collected', 'http_status': 200,
                 'operation': urlsplit(url).path, 'query': kwargs.get('params') or {}}
        if kwargs.get('body'):
            entry['request'] = deepcopy(kwargs['body'])
        if url.endswith(':getAncestry'):
            response = {'ancestor': [{'resourceId': {'type': 'project', 'id': '12345'}}]}
        elif url.endswith(':getIamPolicy'):
            response = {'bindings': [], 'auditConfigs': deepcopy(CONFIGS), 'etag': 'synthetic', 'version': 1}
        elif url.endswith(':searchAllIamPolicies'):
            if self.deny_cai or (self.pending_denial and kwargs.get('params', {}).get('pageToken')):
                from peaso.collectors.gcp import ReadError
                entry['status'], entry['http_status'] = 'denied', 403
                self.evidence.append(entry)
                error = ReadError('denied', 'fixture_denied')
                error.request_id = ref
                raise error
            rows = [{'resource': self.root_name,
                     'assetType': 'cloudresourcemanager.googleapis.com/Project',
                     'project': self.project, 'policy': deepcopy(self.projected)},
                    {'resource': self.peer_name, 'assetType': 'cloudkms.googleapis.com/KeyRing',
                     'project': NUMBER, 'policy': {'bindings': []}},
                    {'resource': CRYPTO, 'assetType': 'cloudkms.googleapis.com/CryptoKey',
                     'project': NUMBER, 'policy': {'bindings': []}}]
            if self.peer_duplicate:
                rows.append({**deepcopy(rows[-2]), 'policy': {'bindings': [
                    {'role': 'roles/viewer', 'members': ['user:x@example.invalid']}]}})
            response = {'results': [] if self.empty_cai_page else rows}
            if self.cai_next_page and not kwargs.get('params', {}).get('pageToken'):
                response['nextPageToken'] = 'synthetic-next-page'
        elif url.endswith('/v3/' + SCOPE):
            response = {'name': 'projects/99999' if self.malformed_project else NUMBER,
                        'projectId': 'fixture-project', 'projectNumber': '12345'}
        else:
            response = {}
        self.evidence.append(entry)
        return response, ref


def run(**kwargs):
    transport = NativeTransport(**kwargs)
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['iam_policy'], 'include_inherited': True,
        'metrics_scopes': False, 'concurrency': 1}}
    snapshot = gcp.GCPCollector(connector, transport=transport).collect()
    collection, status = assess(snapshot)
    return collection, status, transport


def assess(snapshot):
    assert validate(snapshot) == snapshot
    collection = next(row for row in snapshot['collections'] if row['type'] == 'iam_policy')
    statuses = [row['status'] for row in evaluate_snapshot(snapshot, checks=[CHECK])['findings']
                if row['check_id'] == CHECK]
    assert 'FAIL' not in statuses
    return collection, 'PASS' if 'PASS' in statuses else 'UNKNOWN'


def test_project_id_alias_is_independently_proven_with_typed_kms_peers():
    collection, status, transport = run()
    assert collection['coverage_status'] == 'collected'
    assert status == 'PASS'
    assert len(collection['items']) == 4
    assert any(e['url'].endswith('/v3/' + SCOPE) for e in transport.evidence)
    assert len([e for e in transport.evidence if e['url'].endswith(':getIamPolicy')]) == 1


@pytest.mark.parametrize('change', [
    {'project': 'projects/99999'},
    {'root_name': '//cloudresourcemanager.googleapis.com/projects/other-project'},
    {'projected': {'bindings': [{'role': 'roles/viewer', 'members': ['user:x@example.invalid']}]}},
    {'peer_duplicate': True},
    {'peer_name': '//cloudresourcemanager.googleapis.com/projects/forged/locations/us/keyRings/r'},
    {'deny_cai': True},
    {'malformed_project': True},
])
def test_unbound_or_incomplete_alias_stays_unknown(change):
    collection, status, _ = run(**change)
    if 'root_name' not in change:
        assert collection['coverage_status'] == 'partial'
    assert status == 'UNKNOWN'


def connector():
    return {'provider': 'gcp', 'scopes': [SCOPE], 'options': {
        'inventories': ['iam_policy'], 'include_inherited': True,
        'metrics_scopes': False, 'concurrency': 1}}


def cai_projection(item):
    return {'name': item['resource'], **item['policy'], 'assetType': item['assetType'],
            'project': item['project'], '_representation': 'partial'}


@pytest.mark.parametrize('failure', ['page_limit', 'resource_limit'])
@pytest.mark.parametrize('stage', ['before', 'after'])
def test_native_limit_survives_alias_collision_in_both_merge_orders(stage, failure):
    transport = NativeTransport()
    collector = gcp.GCPCollector(connector(), transport=transport)
    if stage == 'before':
        if failure == 'page_limit':
            transport.cai_next_page = transport.empty_cai_page = True
            collector.max_pages = 1
            collector.add('iam_policy', SCOPE, 'iam/cloudasset', lambda: collector.pages(
                'https://cloudasset.googleapis.com/v1/' + SCOPE + ':searchAllIamPolicies',
                SCOPE, key='results'))
            collector.max_pages = None
            transport.cai_next_page = transport.empty_cai_page = False
        else:
            collector.max_items = 0
            collector.add('iam_policy', SCOPE, 'iam/cloudasset', lambda: iter([
                ([{'name': SCOPE, 'bindings': [], '_representation': 'full'}], 'synthetic-page')]))
            collector.max_items = None
        snapshot = collector.collect()
    else:
        collector.collect()
        if failure == 'page_limit':
            transport.cai_next_page = True
            collector.max_pages = 1
            collector.add('iam_policy', SCOPE, 'iam/cloudasset', lambda: collector.pages(
                'https://cloudasset.googleapis.com/v1/' + SCOPE + ':searchAllIamPolicies',
                SCOPE, key='results', transform=cai_projection))
        else:
            collector.max_items = collector.total_items
            collector.add('iam_policy', SCOPE, 'iam/cloudasset', lambda: iter([([
                {'name': ROOT, 'assetType': 'cloudresourcemanager.googleapis.com/Project',
                 'project': NUMBER, 'bindings': [], '_representation': 'partial'},
                {'name': KMS + '-new', 'assetType': 'cloudkms.googleapis.com/KeyRing',
                 'project': NUMBER, 'bindings': [], '_representation': 'partial'}], 'synthetic-page')]))
        collector.annotate_effective_audit()
        snapshot = collector.finish()
    collection, status = assess(snapshot)
    assert collection['coverage_status'] == 'partial'
    assert collection['error']['code'] == failure
    assert status == 'UNKNOWN'
    assert collection['items']
    assert collection['source_requests']


def test_denied_pending_cai_page_preserves_denial_and_partial_rows():
    collection, status, transport = run(cai_next_page=True, pending_denial=True)
    assert collection['coverage_status'] == 'partial'
    assert collection['error']['kind'] == 'denied'
    assert collection['error']['code'] == 'fixture_denied'
    assert status == 'UNKNOWN'
    assert collection['items']
    assert any(row['status'] == 'denied' for row in transport.evidence)


def test_two_substantive_failures_remain_visible_after_alias_collision():
    collector = gcp.GCPCollector(connector(), transport=NativeTransport())
    for code in ('page_limit', 'resource_limit'):
        def failed(code=code):
            raise gcp.ReadError('unavailable', code)
            yield  # keep the normal fetch iterator shape
        collector.add('iam_policy', SCOPE, 'iam/cloudasset', failed)
    collection, status = assess(collector.collect())
    assert collection['coverage_status'] == 'partial'
    assert collection['error']['code'] == 'page_limit'
    assert collection['error']['additional_errors'] == [
        {'kind': 'unavailable', 'code': 'resource_limit'}]
    assert status == 'UNKNOWN'
