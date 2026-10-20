"""Offline native transport and pure consumer tests; no installed hooks required."""
from copy import deepcopy
import io
import json
import socket
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_clouddeploy_source_secret_indicators as adapter
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_clouddeploy_source_secret_review_20261019 as check
from peaso import secret_scanning as scanning

SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1/deliveryPipelines/review/releases/review'
OBJECT = 'private/config.tar.gz'
BUCKET = 'review-log-bucket'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.payload = json.dumps(value).encode() if raw is None else raw
        self.content = self.payload  # Real CRM transport parses the HTTP body.
        self.raw = self
        self.stream = io.BytesIO(self.payload)
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.payload)), 'Content-Type': 'application/json', **(headers or {})}
        self.closed = False
        self.reads = []

    def read(self, n, *, decode_content):
        assert decode_content is False and 0 < n <= 16384
        self.reads.append(n)
        return self.stream.read(n)

    def close(self):
        self.closed = True

    def json(self):
        return json.loads(self.payload)


def release():
    return {'name': NAME, 'skaffoldConfigUri': 'gs://' + BUCKET + '/' + OBJECT}


def archive(text=b'public: configuration\n'):
    import tarfile
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tf:
        entry = tarfile.TarInfo('skaffold.yaml')
        entry.size = len(text)
        tf.addfile(entry, io.BytesIO(text))
    return output.getvalue()


def replies(payload=None, source=None):
    payload = archive() if payload is None else payload
    metadata = {'bucket': BUCKET, 'name': OBJECT, 'generation': '12345',
                'size': str(len(payload)), 'contentType': 'application/gzip'}
    return [Response(source if source is not None else release()), Response(metadata), Response(metadata),
            Response(raw=payload, headers={'Content-Type': 'application/gzip', 'X-Goog-Generation': '12345'})]


def fixture(monkeypatch, responses=None, options=None, mock_engines=True):
    scanning._RESULTS.clear()
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('unmocked socket'))
    if mock_engines:
        monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
        monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
            adapter.OPTION: [NAME], 'metrics_scopes': False, 'include_inherited': False, 'concurrency': 1, 'retries': 0,
            **(options or {})}
    auth = []
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer fake-transport-canary'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    c = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
                         requirements=['project', 'bucket'], transport=transport)
    pending = list(responses if responses is not None else replies())
    calls, received = [], []
    def request(method, url, **kw):
        calls.append((method, url, kw))
        assert method == 'GET'
        if kw.get('stream'):
            assert kw['allow_redirects'] is False
            assert kw['headers']['Accept-Encoding'] == 'identity'
            assert 0 < kw['timeout'] <= transport.timeout
            response = pending.pop(0)
            response.json = lambda: pytest.fail('source passed through JSON cache')
        elif url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            response = Response({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            response = Response({'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}})
        elif url == 'https://storage.googleapis.com/storage/v1/b':
            response = Response({'items': [{'name': BUCKET, 'projectNumber': '10001'}]})
        elif url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            response = Response({'version': 1, 'bindings': []})
        else:
            pytest.fail('unexpected endpoint: ' + url)
        if kw.get('stream'):
            received.append(response)
        return response
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    for kind, scope, service, fetch in c.scope_jobs(SCOPE):
        if kind in ('project', 'bucket'):
            c.collections[(kind, scope)] = c.envelope(kind, scope, service, fetch)
    return c, calls, received, pending, auth


def produce(c):
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    row, = env['items']
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': {**adapter.selection_metadata(c), 'source_requests': deepcopy(c.transport.evidence)}},
             'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]],
                             'bucket': [c.collections[('bucket', SCOPE)]]}}
    return row, index


def test_native_clean_requests_privacy(monkeypatch):
    c, calls, received, pending, _ = fixture(monkeypatch)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', row
    assert evidence['coverage'] == 'observed_object_generation_only'
    assert evidence['historical_release_bytes'] == 'not_established'
    streams = [(u, k) for _, u, k in calls if k.get('stream')]
    assert len(streams) == 4 and not pending
    assert streams[0][0] == 'https://clouddeploy.googleapis.com/v1/' + NAME
    assert streams[0][1]['params'] == {'fields': adapter.RELEASE_FIELDS}
    assert streams[2][1]['params']['generation'] == '12345'
    assert streams[3][1]['params'] == {'generation': '12345', 'ifGenerationMatch': '12345', 'alt': 'media'}
    assert all(r.closed for r in received)
    retained = json.dumps([row, index, evidence]) + repr(c.transport.cache)
    assert all(s not in retained for s in ('public: configuration', 'fake-transport-canary', OBJECT, 'gs://', 'skaffold.yaml'))


@pytest.mark.parametrize('opts', [{'content_secret_scans': False}, {'_content_secret_scan_kinds': None},
    {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': [objects.KIND]}])
def test_disabled_no_credentials(opts):
    c = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], **opts})
    assert adapter.jobs(c, SCOPE) == [] and adapter.collect_sources(c, SCOPE) == []


@pytest.mark.parametrize('selection', [[], [NAME, NAME], [NAME] * 5, [NAME + '?token=secret'],
    [NAME.replace('projects/review/', 'projects/foreign/')], ['https://example.invalid/config'], [{}]])
def test_invalid_selection(selection):
    c = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
                                adapter.OPTION: selection}, scopes=[SCOPE])
    assert adapter.collect_sources(c, SCOPE)[0][adapter.MARKER]['reason'] == 'invalid_selection'


@pytest.mark.parametrize('uri', ['', 'https://example.invalid/private?signature=secret', 'gs://' + BUCKET + '/prefix/',
    'gs://' + BUCKET + '/../source.tar.gz', 'gs://' + BUCKET + '/source.tar.gz#12345',
    'gs://' + BUCKET + '/source.zip', 'gs://' + BUCKET + '/source%2ftar.gz'])
def test_unsupported_binding_no_storage_reads(monkeypatch, uri):
    c, _, received, pending, _ = fixture(monkeypatch, replies(source={**release(), 'skaffoldConfigUri': uri}))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN' and len(received) == 1
    assert uri not in json.dumps(row) if uri else True


@pytest.mark.parametrize('status', [206, 301, 302, 401, 403, 404, 500])
@pytest.mark.parametrize('stage', [0, 1, 2, 3])
def test_denial_partial_redirect_no_fallback(monkeypatch, status, stage):
    responses = replies()
    responses[stage].status_code = status
    c, _, received, _, _ = fixture(monkeypatch, responses)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert len(received) == stage + 1 and all(r.closed for r in received)


@pytest.mark.parametrize('case', ['foreign_project', 'foreign_bucket', 'partial_project', 'partial_bucket',
    'malformed', 'duplicate_json', 'wrong_generation', 'encoding', 'truncated', 'oversize',
    'calls', 'bytes', 'deadline', 'binary', 'empty'])
def test_incomplete_bounds_and_ownership(monkeypatch, case):
    responses = replies(archive(b'\xff\x00') if case == 'binary' else None)
    if case == 'foreign_project': responses[0] = Response({**release(), 'name': NAME.replace('review/', 'foreign/', 1)})
    if case == 'malformed': responses[0] = Response(raw=b'{broken')
    if case == 'duplicate_json': responses[0] = Response(raw=b'{"name":"a","name":"b"}')
    if case == 'wrong_generation': responses[3].headers['X-Goog-Generation'] = '999'
    if case == 'encoding': responses[0].headers['Content-Encoding'] = 'gzip'
    if case == 'truncated': responses[3].headers['Content-Length'] = str(len(responses[3].payload) + 1)
    if case == 'oversize': responses[0].headers['Content-Length'] = str(objects.MAX_METADATA_BYTES + 1)
    if case == 'empty': responses[0] = Response({'name': NAME})
    c, _, received, _, _ = fixture(monkeypatch, responses)
    if case == 'foreign_bucket': c.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '99999'
    if case == 'partial_project': c.collections[('project', SCOPE)]['coverage_status'] = 'partial'
    if case == 'partial_bucket': c.collections[('bucket', SCOPE)]['coverage_status'] = 'partial'
    if case in ('calls', 'bytes', 'deadline'):
        import threading, time
        c.transport._selected_object_secret_state = {'started': time.monotonic() - (31 if case == 'deadline' else 0),
            'bytes': objects.MAX_TOTAL_BYTES if case == 'bytes' else 0,
            'calls': objects.MAX_CALLS if case == 'calls' else 0, 'lock': threading.Lock(), 'items': {}}
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN', row
    assert all(r.closed for r in received)


@pytest.mark.parametrize('case', ['authorization', 'selection', 'global_receipt', 'receipt_status', 'receipt_operation',
    'binding', 'archive', 'coverage', 'partial_bucket', 'bucket_number', 'ownership_receipt', 'duplicate', 'foreign_scope'])
def test_consumer_independent_rejection(monkeypatch, case):
    c, _, _, _, _ = fixture(monkeypatch)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'PASS'
    marker = row[adapter.MARKER]
    if case == 'authorization': index['context']['metadata']['clouddeploy_release_source_authorized'] = False
    if case == 'selection': index['context']['metadata']['selected_clouddeploy_release_ids'] = []
    if case == 'global_receipt': index['context']['metadata']['source_requests'] = []
    if case == 'receipt_status': marker['read_receipts'][0]['status'] = 'denied'
    if case == 'receipt_operation': marker['read_receipts'][0]['operation'] = 'not-source'
    if case == 'binding': marker['binding']['object_id'] = 'gcs-selected-object:' + '0' * 64
    if case == 'archive': marker['archive']['name'] = 'gcs-selected-archive:' + '0' * 64
    if case == 'coverage': row['_coverage'][adapter.MARKER]['status'] = 'unknown'
    if case == 'partial_bucket': index['collections']['bucket'][0]['status'] = 'partial'
    if case == 'bucket_number': index['collections']['bucket'][0]['items'][0]['projectNumber'] = '99999'
    if case == 'ownership_receipt': index['collections']['bucket'][0]['source_requests'] = []
    if case == 'duplicate': index['collections'][adapter.KIND][0]['items'].append(deepcopy(row))
    if case == 'foreign_scope': index['context']['scope'] = 'projects/foreign'
    assert check.evaluate(row, index)[0] == 'UNKNOWN'


def test_real_offline_dual_detector_positive_negative(monkeypatch):
    for text, expected in ((b'public: configuration\n', 'PASS'), (('TOKEN=' + TOKEN + '\n').encode(), 'FAIL')):
        c, _, received, _, _ = fixture(monkeypatch, replies(archive(text)), mock_engines=False)
        row, index = produce(c)
        status, evidence = check.evaluate(row, index)
        assert status == expected, row
        assert all(r.closed for r in received)
        if expected == 'FAIL':
            assert {d['engine'] for l in evidence['secret_leaks'] for d in l['detectors']} == {'kingfisher', 'trufflehog'}
        assert TOKEN not in json.dumps([row, index, evidence]) + repr(c.transport.cache) + repr(scanning._RESULTS)


@pytest.mark.parametrize('engine', ['_scan_kingfisher', '_scan_trufflehog'])
def test_detector_failure_unknown(monkeypatch, engine):
    c, _, _, _, _ = fixture(monkeypatch)
    monkeypatch.setattr(scanning, engine, lambda *a: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN' and TOKEN not in json.dumps(row)


def test_installer_idempotent(monkeypatch):
    from peaso import checks
    from peaso.checks import fixtures
    from peaso.checks.facts import MemoIndex
    monkeypatch.setattr(checks, 'CHECKS', [c for c in checks.CHECKS if c.id != check.CHECK_ID])
    monkeypatch.setattr(fixtures, 'CASES', {k: v for k, v in fixtures.CASES.items() if k != check.CHECK_ID})
    check.install()
    check.install()
    assert sum(c.id == check.CHECK_ID for c in checks.CHECKS) == 1
    cases = fixtures.CASES[check.CHECK_ID]
    for label in ('pass', 'fail', 'unknown'):
        assert check.evaluate(cases[label], MemoIndex(cases[label + '_index']))[0] == label.upper()

def test_shared_archive_two_selected_release_owners(monkeypatch):
    second = NAME + '-second'
    responses = replies()
    responses += [Response({**release(), 'name': second}), Response(json.loads(responses[1].payload))]
    c, calls, received, pending, _ = fixture(monkeypatch, responses, options={adapter.OPTION: [NAME, second]})
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': {
        **adapter.selection_metadata(c), 'source_requests': deepcopy(c.transport.evidence)}},
        'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]],
                        'bucket': [c.collections[('bucket', SCOPE)]]}}
    assert [check.evaluate(r, index)[0] for r in env['items']] == ['PASS', 'PASS']
    assert len(received) == 6 and not pending
    assert sum((kw.get('params') or {}).get('alt') == 'media' for _, _, kw in calls) == 1
    assert c.options['_content_secret_scan_kinds'] == [adapter.KIND]
    assert 'selected_gcs_archives' not in c.options


@pytest.mark.parametrize('case', ['traversal', 'nested', 'empty_archive', 'too_many_members'])
def test_unsupported_archive_members_unknown(monkeypatch, case):
    import tarfile
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as tf:
        names = [] if case == 'empty_archive' else (['../escape.yaml'] if case == 'traversal' else
            ['nested.zip'] if case == 'nested' else ['file-' + str(i) for i in range(101)])
        for name in names:
            data = b'public\n'
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tf.addfile(entry, io.BytesIO(data))
    c, _, received, _, _ = fixture(monkeypatch, replies(output.getvalue()))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN' and all(r.closed for r in received)


def test_signed_uri_and_provider_plaintext_never_retained(monkeypatch):
    raw = {'name': NAME, 'skaffoldConfigUri': 'https://example.invalid/source?X-Goog-Signature=' + TOKEN,
           'description': TOKEN, 'deployParameters': {'token': TOKEN}}
    c, _, received, _, _ = fixture(monkeypatch, replies(source=raw))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN' and len(received) == 1
    assert TOKEN not in json.dumps([row, index]) + repr(c.transport.cache)
