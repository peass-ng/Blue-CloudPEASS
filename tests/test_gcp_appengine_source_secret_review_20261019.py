"""Offline native transport cases; pytest execution belongs to the coordinator."""
from copy import deepcopy
import hashlib
import io
import json
import socket
from types import SimpleNamespace

import pytest
from peaso.collectors import gcp
from peaso.collectors import gcp_appengine_source_secret_indicators as adapter
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_appengine_source_secret_review_20261019 as check
from peaso import secret_scanning as scanning

SCOPE = 'projects/review'
NAME = 'apps/review/services/default/versions/v1'
BUCKET = 'review-source-bucket'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
QUERY = 'X-Goog-Signature=private-query-canary&X-Goog-Credential=private-identity-canary'


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.payload = json.dumps(value).encode() if raw is None else raw
        self.raw = self
        self.stream = io.BytesIO(self.payload)
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.payload)), 'Content-Type': 'application/json', **(headers or {})}
        self.closed = False

    def read(self, n, *, decode_content):
        assert decode_content is False and 0 < n <= 16384
        return self.stream.read(n)

    def close(self):
        self.closed = True

    def json(self):
        return json.loads(self.payload)


def version(payload=b'print("hello")\n'):
    return {'name': NAME, 'id': 'v1', 'env': 'standard', 'deployment': {'files': {
        'main.py': {'sourceUrl': 'https://storage.googleapis.com/' + BUCKET + '/source/main.py?' + QUERY,
                    'sha1Sum': hashlib.sha1(payload).hexdigest()}}}}


def replies(payload=b'print("hello")\n', source=None):
    metadata = {'bucket': BUCKET, 'name': 'source/main.py', 'generation': '12345',
                'size': str(len(payload)), 'contentType': 'text/plain'}
    return [Response({'name': 'apps/review', 'id': 'review'}), Response(version(payload) if source is None else source),
            Response(metadata), Response(metadata),
            Response(raw=payload, headers={'Content-Type': 'text/plain', 'X-Goog-Generation': '12345'})]


def fixture(monkeypatch, responses=None, options=None, real_engines=False):
    scanning._RESULTS.clear()
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('unmocked socket'))
    if not real_engines:
        monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
        monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], adapter.OPTION: [NAME],
            'metrics_scopes': False, 'include_inherited': False, 'concurrency': 1, 'retries': 0, **(options or {})}
    auth = []
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer fake-appengine-auth-canary'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
                               requirements=['project', 'bucket'], transport=transport)
    pending = list(replies() if responses is None else responses)
    calls, received = [], []
    def request(method, url, **kw):
        calls.append((method, url, kw))
        assert method == 'GET'
        if kw.get('stream'):
            assert kw['allow_redirects'] is False
            assert kw['headers']['Accept-Encoding'] == 'identity'
            assert 0 < kw['timeout'] <= transport.timeout
            response = pending.pop(0)
            response.json = lambda: pytest.fail('sensitive source passed through global JSON cache')
            received.append(response)
        elif url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            response = Response({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            response = Response({'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}})
        elif url == 'https://storage.googleapis.com/storage/v1/b':
            response = Response({'items': [{'name': BUCKET, 'projectNumber': '10001'}]})
        elif url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            response = Response({'version': 1, 'bindings': []})
        else:
            pytest.fail('unexpected native endpoint: ' + url)
        return response
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    for kind, scope, service, fetch in collector.scope_jobs(SCOPE):
        if kind in ('project', 'bucket'):
            collector.collections[(kind, scope)] = collector.envelope(kind, scope, service, fetch)
    return collector, calls, received, pending, auth


def produce(collector):
    kind, scope, service, fetch = adapter.jobs(collector, SCOPE)[0]
    env = collector.envelope(kind, scope, service, fetch)
    row, = env['items']
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(collector)},
             'collections': {kind: [env], 'project': [collector.collections[('project', SCOPE)]],
                             'bucket': [collector.collections[('bucket', SCOPE)]]}}
    return row, index


def test_native_positive_and_privacy(monkeypatch):
    c, calls, received, pending, _ = fixture(monkeypatch)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', row
    assert evidence['coverage'] == 'complete_native_deployment_files_manifest_only'
    assert evidence['files'] == 1 and len(evidence['source_requests']) == 7
    native = [(u, kw) for _, u, kw in calls if kw.get('stream')]
    assert len(native) == 5 and not pending
    assert native[0][0] == 'https://appengine.googleapis.com/v1/apps/review'
    assert native[1] == ('https://appengine.googleapis.com/v1/' + NAME, native[1][1])
    assert native[1][1]['params'] == {'view': 'FULL', 'fields': adapter.VERSION_FIELDS}
    assert native[2][0] == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/o/source%2Fmain.py'
    assert native[3][1]['params']['generation'] == native[3][1]['params']['ifGenerationMatch'] == '12345'
    assert native[4][1]['params'] == {'generation': '12345', 'ifGenerationMatch': '12345', 'alt': 'media'}
    assert all(r.closed for r in received)
    serialized = json.dumps([row, c.transport.evidence, evidence, index]) + repr(c.transport.cache)
    for private in ('private-query-canary', 'private-identity-canary', 'fake-appengine-auth-canary', 'print(', 'sourceUrl'):
        assert private not in serialized
    assert all('?' not in u and 'X-Goog-' not in json.dumps(kw['params']) for u, kw in native)


@pytest.mark.parametrize('options', [
    {'content_secret_scans': False}, {'content_secret_scans': 'true'}, {'_content_secret_scan_kinds': []},
    {'_content_secret_scan_kinds': None}, {'_content_secret_scan_kinds': adapter.KIND},
    {'_content_secret_scan_kinds': [objects.KIND]},
])
def test_default_off_zero_calls(options):
    c = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], **options})
    assert adapter.jobs(c, SCOPE) == [] and adapter.collect_sources(c, SCOPE) == []
    assert check.evaluate({}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('selection', [None, [], [NAME] * 2, [NAME] * 5, ['apps/other/services/default/versions/latest'],
    [NAME + '?token=hidden'], ['apps/review/services/default/versions/*'],
    ['apps/other/services/default/versions/v1'], [NAME, 'apps/other/services/default/versions/v1']])
def test_invalid_selection_zero_requests(monkeypatch, selection):
    c, calls, _, _, auth = fixture(monkeypatch)
    c.options[adapter.OPTION] = selection
    start, credentials = len(calls), len(auth)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert len(calls) == start and len(auth) == credentials


@pytest.mark.parametrize('mutation', ['hash_missing', 'hash_wrong', 'external', 'non_native', 'container', 'binary',
                                      'missing', 'too_many', 'wrong_name', 'partial', 'ambiguous'])
def test_unsupported_or_unbound_stays_unknown(monkeypatch, mutation):
    payload = b'\x00binary' if mutation == 'binary' else b'print("hello")\n'
    source = version(payload)
    info = source['deployment']['files']['main.py']
    if mutation == 'hash_missing':
        info.pop('sha1Sum')
    elif mutation == 'hash_wrong':
        info['sha1Sum'] = '0' * 40
        monkeypatch.setattr(adapter, 'scan_content', lambda *a, **kw: pytest.fail('scan before hash match'))
    elif mutation == 'external':
        info['sourceUrl'] = 'https://attacker.invalid/file?' + QUERY
    elif mutation == 'non_native':
        info['sourceUrl'] = 'gs://' + BUCKET + '/source/main.py'
    elif mutation == 'container':
        source['deployment']['container'] = {'image': 'external'}
    elif mutation == 'missing':
        source['deployment'] = {}
    elif mutation == 'too_many':
        source['deployment']['files'] = {str(i): info for i in range(adapter.MAX_FILES + 1)}
    elif mutation == 'wrong_name':
        source['name'] = NAME + '-other'
    elif mutation == 'partial':
        source['_coverage'] = {'deployment': {'status': 'unknown'}}
    elif mutation == 'ambiguous':
        source['deployment']['files']['other.py'] = deepcopy(info)
    c, _, _, _, _ = fixture(monkeypatch, responses=replies(payload, source))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert 'private-query-canary' not in json.dumps([row, c.transport.evidence]) + repr(c.transport.cache)


@pytest.mark.parametrize('at', range(5))
def test_denial_is_unknown(monkeypatch, at):
    responses = replies()
    responses[at] = Response({'error': QUERY}, status=403)
    c, _, received, _, _ = fixture(monkeypatch, responses=responses)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert all(r.closed for r in received)
    assert QUERY not in json.dumps([row, c.transport.evidence])


@pytest.mark.parametrize('mutation', ['project', 'bucket', 'native_ref', 'owner', 'receipt', 'manifest_count',
                                      'hash', 'hash_value', 'detector', 'generation', 'generation_value', 'duplicate', 'coverage'])
def test_consumer_rejects_foreign_or_partial_evidence(monkeypatch, mutation):
    c, _, _, _, _ = fixture(monkeypatch)
    row, index = produce(c)
    marker = row[adapter.MARKER]
    if mutation == 'project':
        index['collections']['project'][0]['items'][0]['projectId'] = 'other'
    elif mutation == 'bucket':
        index['collections']['bucket'][0]['items'][0]['projectNumber'] = '999'
    elif mutation == 'native_ref':
        marker['native_requests'].append('request-999')
    elif mutation == 'owner':
        marker['read_receipts'][-1]['resource_id'] = 'gcs-selected-object:' + '0' * 64
    elif mutation == 'receipt':
        marker['read_receipts'][-1]['http_status'] = 206
    elif mutation == 'manifest_count':
        marker['manifest_count'] += 1
    elif mutation == 'hash':
        marker['files'][0]['hash_matches'] = False
    elif mutation == 'hash_value':
        marker['files'][0]['sha1'] = '0' * 40
    elif mutation == 'generation_value':
        marker['files'][0]['generation'] = '99999'
    elif mutation == 'detector':
        marker['files'][0]['object'][objects.MARKER]['engines'][0]['status'] = 'incomplete'
    elif mutation == 'generation':
        marker['files'][0]['generation'] = 'latest'
    elif mutation == 'duplicate':
        index['collections'][adapter.KIND][0]['items'].append(deepcopy(row))
    elif mutation == 'coverage':
        index['collections'][adapter.KIND][0]['coverage_status'] = 'partial'
    assert check.evaluate(row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mutation', ['length', 'range', 'generation', 'encoding', 'byte_limit', 'call_limit', 'deadline', 'cancel'])
def test_transport_bounds(monkeypatch, mutation):
    responses = replies()
    if mutation == 'length':
        responses[-1].headers['Content-Length'] = '999999999'
    elif mutation == 'range':
        responses[-1].headers['Content-Range'] = 'bytes 0-3/100'
    elif mutation == 'generation':
        responses[-1].headers['X-Goog-Generation'] = '999'
    elif mutation == 'encoding':
        responses[-1].headers['Content-Encoding'] = 'gzip'
    c, calls, received, _, _ = fixture(monkeypatch, responses=responses)
    if mutation == 'byte_limit':
        monkeypatch.setattr(adapter, 'MAX_BYTES', 1)
    elif mutation == 'call_limit':
        c.transport.max_calls = c.transport.calls
    elif mutation == 'deadline':
        c.transport.deadline = 0
    elif mutation == 'cancel':
        monkeypatch.setattr(c.transport, 'check_cancelled', lambda: (_ for _ in ()).throw(RuntimeError('cancel')))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert all(r.closed for r in received)


def test_real_offline_detectors_clean_and_secret(monkeypatch):
    for payload, expected in ((b'print("hello")\n', 'PASS'), (('GITHUB_TOKEN=' + TOKEN + '\n').encode(), 'FAIL')):
        with monkeypatch.context() as mp:
            c, _, _, _, _ = fixture(mp, responses=replies(payload), real_engines=True)
            row, index = produce(c)
            status, evidence = check.evaluate(row, index)
            assert status == expected, row
            assert TOKEN not in json.dumps([row, evidence, c.transport.evidence]) + repr(c.transport.cache)
            if expected == 'FAIL':
                assert evidence['secret_leaks'] and evidence['credential_validation'] == 'not_attempted'


def test_install_idempotent():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    before = sum(c.id == check.CHECK_ID for c in CHECKS)
    check.install()
    check.install()
    assert sum(c.id == check.CHECK_ID for c in CHECKS) == 1
    assert check.CHECK_ID in CASES
    if before == 0:
        CHECKS[:] = [c for c in CHECKS if c.id != check.CHECK_ID]
        CASES.pop(check.CHECK_ID, None)


@pytest.mark.parametrize('mutation', ['app', 'bucket', 'project', 'project_coverage', 'bucket_coverage', 'project_receipt'])
def test_native_identity_fail_closed(monkeypatch, mutation):
    responses = replies()
    if mutation == 'app':
        responses[0] = Response({'name': 'apps/other', 'id': 'other'})
    c, calls, _, _, _ = fixture(monkeypatch, responses=responses)
    if mutation == 'bucket':
        c.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '999'
    elif mutation == 'project':
        c.collections[('project', SCOPE)]['items'][0]['projectId'] = 'other'
    elif mutation == 'project_coverage':
        c.collections[('project', SCOPE)]['items'][0]['_coverage'] = {'projectId': {'status': 'unknown'}}
    elif mutation == 'bucket_coverage':
        c.collections[('bucket', SCOPE)]['items'][0]['_coverage'] = {'projectNumber': {'status': 'unknown'}}
    elif mutation == 'project_receipt':
        c.collections[('project', SCOPE)]['items'][0]['_provenance']['source_requests'] = ['request-999']
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert not any(u.startswith('https://storage.googleapis.com/') and kw.get('stream') for _, u, kw in calls)


def test_subset_never_yields_clean_manifest(monkeypatch):
    payload = b'print("hello")\n'
    source = version(payload)
    source['deployment']['files']['second.py'] = {'sourceUrl': 'https://storage.googleapis.com/' + BUCKET + '/second.py',
                                                'sha1Sum': hashlib.sha1(payload).hexdigest()}
    responses = replies(payload, source)
    responses.append(Response({'error': QUERY}, status=403))
    c, _, _, _, _ = fixture(monkeypatch, responses=responses)
    row, index = produce(c)
    assert len(row[adapter.MARKER]['files']) == 1
    assert row[adapter.MARKER]['manifest_count'] == 2
    assert row[adapter.MARKER]['complete'] is False
    assert check.evaluate(row, index)[0] == 'UNKNOWN'


def test_detector_failure_unknown(monkeypatch):
    c, _, _, _, _ = fixture(monkeypatch)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: (_ for _ in ()).throw(RuntimeError('engine unavailable')))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('count', [2, 3, 4])
def test_complete_bounded_native_manifests(monkeypatch, count):
    payload = b'print("hello")\n'
    source = version(payload)
    responses = replies(payload, source)[:2]
    source['deployment']['files'] = {}
    for i in range(count):
        obj = 'source/file' + str(i) + '.py'
        source['deployment']['files'][obj] = {'sourceUrl': 'https://storage.googleapis.com/' + BUCKET + '/' + obj + '?' + QUERY,
                                            'sha1Sum': hashlib.sha1(payload).hexdigest()}
        meta = {'bucket': BUCKET, 'name': obj, 'generation': str(12345 + i), 'size': str(len(payload)), 'contentType': 'text/plain'}
        responses += [Response(meta), Response(meta), Response(raw=payload, headers={'Content-Type': 'text/plain', 'X-Goog-Generation': str(12345 + i)})]
    responses[1] = Response(source)
    c, _, _, pending, _ = fixture(monkeypatch, responses=responses)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', row
    assert evidence['files'] == count and not pending


def test_four_explicit_versions(monkeypatch):
    names = [NAME[:-1] + str(i) for i in range(1, 5)]
    responses = []
    for name in names:
        source = version()
        source.update(name=name, id=name.split('/')[-1])
        responses += replies(source=source)
    c, _, _, pending, _ = fixture(monkeypatch, responses=responses, options={adapter.OPTION: names})
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(c)},
             'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]], 'bucket': [c.collections[('bucket', SCOPE)]]}}
    assert len(env['items']) == 4 and not pending
    assert [check.evaluate(row, index)[0] for row in env['items']] == ['PASS'] * 4
    assert c.transport._selected_object_secret_state['calls'] == 20
