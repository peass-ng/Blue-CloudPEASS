"""Offline native transport and pure consumer tests; no installed hooks required."""
from copy import deepcopy
import io
import json
import socket
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_cloudbuild_log_secret_indicators as adapter
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_cloudbuild_log_secret_review_20261019 as check
from peaso import secret_scanning as scanning

SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1/builds/12345678-abcd-1234-abcd-123456789abc'
BUCKET = 'review-log-bucket'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.payload = json.dumps(value).encode() if raw is None else raw
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


def build():
    return {'name': NAME, 'id': NAME.split('/')[-1], 'projectId': 'review',
            'logsBucket': 'gs://' + BUCKET, 'status': 'SUCCESS',
            'createTime': '2026-10-19T10:00:00Z', 'startTime': '2026-10-19T10:00:01Z',
            'finishTime': '2026-10-19T10:00:05Z', 'options': {'logging': 'GCS_ONLY'}}


def replies(payload=b'build completed\n', source=None):
    metadata = {'bucket': BUCKET, 'name': 'log-' + NAME.split('/')[-1] + '.txt',
                'generation': '12345', 'size': str(len(payload)), 'contentType': 'text/plain'}
    return [Response(source if source is not None else build()), Response(metadata), Response(metadata),
            Response(raw=payload, headers={'Content-Type': 'text/plain', 'X-Goog-Generation': '12345'})]


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
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(c)},
             'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]],
                             'bucket': [c.collections[('bucket', SCOPE)]]}}
    return row, index


def test_native_clean_exact_requests_and_generation_evidence(monkeypatch):
    c, calls, received, pending, _ = fixture(monkeypatch)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', row
    assert evidence['coverage'] == 'observed_object_generation_only'
    assert evidence['historical_build_log_completion'] == 'not_established'
    assert evidence['generation'] == '12345' and len(evidence['source_requests']) == 6
    content = [(m, u, kw) for m, u, kw in calls if kw.get('stream')]
    assert len(content) == 4 and not pending
    assert content[0][1] == 'https://cloudbuild.googleapis.com/v1/' + NAME
    assert content[0][2]['params'] == {'fields': adapter.BUILD_FIELDS}
    expected_url = 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/o/log-' + NAME.split('/')[-1] + '.txt'
    assert all(u == expected_url for _, u, _ in content[1:])
    assert content[1][2]['params'] == {'fields': objects.FIELDS, 'projection': 'noAcl'}
    assert content[2][2]['params'] == {'fields': objects.FIELDS, 'projection': 'noAcl',
                                    'generation': '12345', 'ifGenerationMatch': '12345'}
    assert content[3][2]['params'] == {'generation': '12345', 'ifGenerationMatch': '12345', 'alt': 'media'}
    assert all(r.closed for r in received)
    assert all(len(r.payload) <= objects.MAX_METADATA_BYTES for r in received)
    serialized = json.dumps([row, c.transport.evidence, evidence]) + repr(c.transport.cache)
    assert 'build completed' not in serialized and 'fake-transport-canary' not in serialized
    assert 'gs://' not in json.dumps(row) and BUCKET not in json.dumps(row)


@pytest.mark.parametrize('options', [
    {'content_secret_scans': False}, {'content_secret_scans': 'true'},
    {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': None},
    {'_content_secret_scan_kinds': adapter.KIND}, {'_content_secret_scan_kinds': [objects.KIND]},
])
def test_optout_zero_adapter_calls(monkeypatch, options):
    # Use a transport-free facade to prove that disabled paths cannot acquire credentials.
    c = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], **options})
    assert adapter.jobs(c, SCOPE) == []
    assert adapter.collect_sources(c, SCOPE) == []
    assert check.evaluate({}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('selection,scopes', [
    ([], [SCOPE]), ([NAME] * 2, [SCOPE]), ([NAME] * 5, [SCOPE]),
    (['https://console.cloud.google.com/cloud-build/builds/1234'], [SCOPE]),
    ([NAME.replace('review/', 'foreign/')], [SCOPE]),
    ([NAME.replace('us-central1', '*')], [SCOPE]), ([NAME], [SCOPE, 'projects/other']),
    ([NAME + '?x=y'], [SCOPE]), ([{}], [SCOPE]),
])
def test_invalid_selection_before_credentials(selection, scopes):
    c = SimpleNamespace(options={'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
                                adapter.OPTION: selection}, scopes=scopes)
    rows = adapter.collect_sources(c, SCOPE)
    assert len(rows) == 1 and rows[0][adapter.MARKER]['complete'] is False
    assert rows[0][adapter.MARKER]['reason'] == 'invalid_selection'


@pytest.mark.parametrize('change', [
    {'status': 'WORKING'}, {'projectId': 'foreign'}, {'name': NAME + 'x'}, {'id': 'foreign'},
    {'logsBucket': ''}, {'logsBucket': 'https://console.cloud.google.com/logs'},
    {'logsBucket': 'gs://' + BUCKET + '/prefix'}, {'options': {'logging': 'CLOUD_LOGGING_ONLY'}},
    {'options': {'logging': 'NONE'}}, {'finishTime': 'bad'}, {'warning': 'partial'},
    {'logsBucket': 'gs://foreign-bucket'}, {'_coverage': {'logsBucket': {'status': 'unknown'}}},
])
def test_unsupported_build_unknown_before_object_reads(monkeypatch, change):
    b = {**build(), **change}
    c, calls, _, pending, _ = fixture(monkeypatch, replies(source=b))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['complete'] is False
    assert len([kw for _, _, kw in calls if kw.get('stream')]) == 1
    assert len(pending) == 3


@pytest.mark.parametrize('stage,status', [(0, 403), (1, 404), (2, 412), (3, 403), (3, 206)])
def test_denied_missing_and_partial_unknown(monkeypatch, stage, status):
    responses = replies()
    responses[stage].status_code = status
    c, _, received, _, _ = fixture(monkeypatch, responses)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['complete'] is False
    assert all(r.closed for r in received)


@pytest.mark.parametrize('stage,raw,headers', [
    (0, b'{"id":"a","id":"b"}', {}), (1, b'[]', {}),
    (1, b'x' * (objects.MAX_METADATA_BYTES + 1), {}),
    (0, b'{}', {'Content-Length': '100'}),
    (1, b'{}', {'Content-Encoding': 'gzip'}),
    (3, b'build completed\n', {'X-Goog-Generation': '999'}),
])
def test_malformed_truncated_oversize_or_changed_generation_unknown(monkeypatch, stage, raw, headers):
    responses = replies()
    responses[stage] = Response(raw=raw, headers=headers)
    c, _, received, _, _ = fixture(monkeypatch, responses)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert all(r.closed for r in received)
    if len(raw) > objects.MAX_METADATA_BYTES:
        assert received[-1].reads == []  # reject declared oversized body before reading


@pytest.mark.parametrize('change', ['project', 'bucket', 'receipts', 'authorization', 'generation', 'engines', 'scope'])
def test_consumer_rejects_missing_forged_or_incomplete_proofs(monkeypatch, change):
    c, _, _, _, _ = fixture(monkeypatch)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'PASS'
    if change == 'project':
        index['collections']['project'][0]['items'][0]['name'] = 'projects/999'
    elif change == 'bucket':
        index['collections']['bucket'][0]['items'][0]['projectNumber'] = '999'
    elif change == 'receipts':
        row[adapter.MARKER]['read_receipts'][0]['resource_id'] = 'foreign'
    elif change == 'authorization':
        index['context']['metadata']['cloudbuild_log_source_authorized'] = False
    elif change == 'generation':
        row[adapter.MARKER]['generation'] = '999'
    elif change == 'engines':
        row[adapter.MARKER]['object'][objects.MARKER]['engines'].pop()
    else:
        index['context']['scope'] = 'projects/foreign'
    assert check.evaluate(row, index)[0] == 'UNKNOWN'


def test_detector_failure_and_non_text_are_unknown(monkeypatch):
    for payload in (b'\xff\x00', b'\x1f\x8bmalformed'):
        c, _, _, _, _ = fixture(monkeypatch, replies(payload))
        row, index = produce(c)
        assert check.evaluate(row, index)[0] == 'UNKNOWN'
    c, _, _, _, _ = fixture(monkeypatch)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: (_ for _ in ()).throw(RuntimeError('fake secret')))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert 'fake secret' not in json.dumps(row)


def test_install_explicit_idempotent(monkeypatch):
    from peaso import checks
    from peaso.checks import fixtures
    original = list(checks.CHECKS)
    monkeypatch.setattr(checks, 'CHECKS', original)
    monkeypatch.setattr(fixtures, 'CASES', dict(fixtures.CASES))
    check.install()
    check.install()
    assert sum(c.id == check.CHECK_ID for c in checks.CHECKS) == 1
    assert check.DECLARATION['finding_type'] == 'secrets'
    assert check.DECLARATION['requirements'] == []


def test_native_positive_dual_detector_redaction(monkeypatch):
    payload = ('token="' + TOKEN + '"\n').encode()
    c, _, _, _, _ = fixture(monkeypatch, replies(payload))
    seen = []
    def detect(content, path, timeout):
        assert content == payload and path == 'object.content'
        seen.append(True)
        return [(TOKEN, 'github-token', 1)]
    monkeypatch.setattr(scanning, '_scan_kingfisher', detect)
    monkeypatch.setattr(scanning, '_scan_trufflehog', detect)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'FAIL' and len(seen) == 2
    leak, = evidence['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert evidence['credential_validation'] == 'not_attempted'
    assert TOKEN not in json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
    assert TOKEN not in repr(scanning._RESULTS)


@pytest.mark.parametrize('mutation', ['project_receipt', 'bucket_receipt', 'bucket_owner', 'project_coverage',
                                      'call_limit', 'cancel', 'deadline', 'generation_missing', 'empty_log'])
def test_missing_native_bindings_and_limits_unknown(monkeypatch, mutation):
    responses = replies(b'' if mutation == 'empty_log' else b'build completed\n')
    if mutation == 'generation_missing':
        metadata = json.loads(responses[1].payload)
        del metadata['generation']
        responses[1] = Response(metadata)
    c, calls, _, _, _ = fixture(monkeypatch, responses)
    if mutation == 'project_receipt':
        c.collections[('project', SCOPE)]['items'][0]['_provenance']['source_requests'] = []
    elif mutation == 'bucket_receipt':
        c.collections[('bucket', SCOPE)]['items'][0]['_provenance']['source_requests'] = []
    elif mutation == 'bucket_owner':
        c.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '999'
    elif mutation == 'project_coverage':
        c.collections[('project', SCOPE)]['coverage_status'] = 'partial'
    elif mutation == 'call_limit':
        c.transport.max_calls = c.transport.calls
    elif mutation == 'cancel':
        monkeypatch.setattr(c.transport, 'check_cancelled', lambda: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    elif mutation == 'deadline':
        c.transport.deadline = 1
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([row, c.transport.evidence])
    if mutation in ('project_receipt', 'project_coverage', 'call_limit', 'cancel', 'deadline'):
        assert not any(kw.get('stream') for _, _, kw in calls)


def test_real_offline_dual_detector_positive_and_negative(monkeypatch):
    for payload, expected in ((('token="' + TOKEN + '"\n').encode(), 'FAIL'),
                              (b'build completed successfully\n', 'PASS')):
        c, _, _, _, _ = fixture(monkeypatch, replies(payload), mock_engines=False)
        row, index = produce(c)
        status, evidence = check.evaluate(row, index)
        assert status == expected, row
        assert {e['engine'] for e in evidence['engines']} == {'kingfisher', 'trufflehog'}
        if expected == 'FAIL':
            leak, = evidence['secret_leaks']
            assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
        assert TOKEN not in json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
        assert TOKEN not in repr(scanning._RESULTS)


def test_redacted_native_fixture_contract():
    import gzip
    from pathlib import Path
    path = Path(check.__file__).with_name('gcp_cloudbuild_log_secret_review_20261019_fixtures.json.gz')
    assert path.stat().st_size < 8192
    raw = gzip.decompress(path.read_bytes())
    assert TOKEN.encode() not in raw
    cases = json.loads(raw)
    for label, expected in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        assert check.evaluate(cases[label], cases[label + '_index'])[0] == expected
    assert check.evaluate(cases['missing'], {})[0] == 'UNKNOWN'
    assert check.evaluate(cases['malformed'], {})[0] == 'UNKNOWN'


def test_four_builds_share_bounded_reader_budget(monkeypatch):
    names, responses = [], []
    for n in range(4):
        name = NAME + str(n)
        names.append(name)
        batch = replies()
        b = build()
        b.update(name=name, id=name.split('/')[-1])
        batch[0] = Response(b)
        meta = json.loads(batch[1].payload)
        meta['name'] = 'log-' + b['id'] + '.txt'
        batch[1], batch[2] = Response(meta), Response(meta)
        responses.extend(batch)
    c, calls, _, pending, _ = fixture(monkeypatch, responses, options={adapter.OPTION: names})
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    ix = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(c)},
          'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]],
                          'bucket': [c.collections[('bucket', SCOPE)]]}}
    assert len(env['items']) == 4 and not pending
    assert all(check.evaluate(row, ix)[0] == 'PASS' for row in env['items'])
    assert len([kw for _, _, kw in calls if kw.get('stream')]) == 16
    state = c.transport._selected_object_secret_state
    assert state['calls'] == 16 and state['bytes'] == 4 * len(b'build completed\n')


@pytest.mark.parametrize('mutation', ['object_oversize', 'metadata_stream_limit', 'partial_header'])
def test_explicit_byte_and_range_bounds(monkeypatch, mutation):
    responses = replies()
    if mutation == 'object_oversize':
        meta = json.loads(responses[1].payload)
        meta['size'] = str(objects.MAX_OBJECT_BYTES + 1)
        responses[1] = Response(meta)
    elif mutation == 'metadata_stream_limit':
        responses[1] = Response(raw=b' ' * (objects.MAX_METADATA_BYTES + 100))
        del responses[1].headers['Content-Length']
    else:
        responses[1].headers['Content-Range'] = 'bytes 0-5/100'
    c, _, received, _, _ = fixture(monkeypatch, responses)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert len(received) == 2
    if mutation == 'metadata_stream_limit':
        assert responses[1].stream.tell() == objects.MAX_METADATA_BYTES + 1
    elif mutation == 'partial_header':
        assert responses[1].reads == []
